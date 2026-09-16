rule ARKBIRD_SOLG_MAL_Gmera_June_2021_1: FILE {
  meta:
    description = "Detect Gmera malware"
    author      = "Arkbird_SOLG"
    id          = "e1234dc9-b42b-5f54-86cb-ad1b13e9e98d"
    date        = "2021-06-23"
    modified    = "2021-06-24"
    reference   = "https://twitter.com/BushidoToken/status/1407671196322258948"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-23/MAL_Gmera_June_2021_1.yara#L1-L25"
    license_url = "N/A"
    logic_hash  = "9a08c46e0c4d4dd83c1373dd3d7e78d8ed466d3822816880600be1a7d7d69d99"
    score       = 75
    quality     = 63
    tags        = "FILE"
    hash1       = "80e58eb314d0d5e1a50be0c5fca0ca42cdda5e5297d6f7a2590840ac60504be1"
    hash2       = "880df9db805c3e381fd1f71deb664422d725168088b1083c651525dfce5cb033"
    hash3       = "f7921c6b24ab9ac840dbb414a98a0800859ab8d1e5737d551a7939e177c4e2a6"
    tlp         = "White"
    adversary   = "-"

  strings:
    $s1 = "' | base64 -D | sh" fullword ascii
    $s2 = "\" > /dev/null 2>&1 </dev/null &)"
    $s3 = "__mh_execute_header" fullword ascii
    $s4 = "gYXdrICcvU2VyaWFsLyB7cHJpbnQgJDR9"
    $s5 = "IyEgL2Jpbi9iYXNoCgpmdW5jdGlvbiByZW1vdmVfc3BlY19jaGFyKCl7CiAgICBlY2hvICIkMSIgfCB0ciAtZGMgJ1s6YWxudW06XS5ccicgfCB0ciAnWzp1cHBlcjpdJyAnWzpsb3dlcjpdJwp9"
    $s6 = "8ke3dob2FtaX0mJHtpcH0iCgp"
    $s7 = "8IGdyZXAgLWUgTWFudWZhY3R1cmVyIC1lICdWZW5kb3IgTmFtZScgfCBncmVwIC1FICJpcnR1YWx8cmFjbGV8d2FyZXxhcmFsbGVscyI"
    $s8 = { 62 61 73 68 20 2d 69 20 3e 2f 64 65 76 2f 74 63 70 2f [8-25] 30 3e 26 31 }

  condition:
    (uint32(0) == 0xfeedfacf or uint32(0) == 0xbebafeca) and filesize > 35KB and 5 of ($s*)
}