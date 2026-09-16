rule _20160516_aca2989909c752ed3025afe6b42dd2c6_20160517_58379586423d_1226 {
  meta:
    description = "datamaliciousorder - from files 20160516_aca2989909c752ed3025afe6b42dd2c6.js, 20160517_58379586423da2120f54cb14e4074b26.js, 20160517_5a82b782c6f771d21c8dc02d1495bffa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b93b27fc57e8ed0705370dd37064b4ad062165488e715a1f6b4d77bfdf9dd3c6"
    hash2       = "c45ddb6bedaf33180e118398658cfd82f8bb3a8925dfa001758e4d145a802309"
    hash3       = "ab43c26f0457f21b278d69c34b89a575d5e4fcad1b03f0b8b0c0e2d109267a03"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* q  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* q  */ = (123, Turkey); return devel0 /* q  */;};" fullword ascii
    $s3 = "function Scott /* q  */(accinp0 /* q  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "function Scott /* q  */(accinp0 /* q  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "place = /* q  */(/* q  */\"noitisop\").split(''/* q  */).reverse(/* q  */).join('');" fullword ascii
    $s6 = "DENMARK1 /* q  */= true;/* q  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}