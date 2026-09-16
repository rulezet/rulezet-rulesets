rule _20160517_00607661cd6e99d5fddfdf1dded424d3_20160517_458f22ce429a_1227 {
  meta:
    description = "datamaliciousorder - from files 20160517_00607661cd6e99d5fddfdf1dded424d3.js, 20160517_458f22ce429a0089a4db4582b48ac3da.js, 20160517_d1d67533d440728fa3d6e8ff2b6bb897.js, 20160517_ee90f4e26e02493b00dd4c29ebca80c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a552a72a2b2379d087bcd42a75d9b8ac927e10795626ada96e8f5f4b4232ec5"
    hash2       = "4aa991c2d030c9ed4f5bccd3af7b7f6411cf9fcd0eb12e636193d25f644a2ee7"
    hash3       = "2a06e122885a51ccc4ac5b30ac0e7e3dbec503ea6a607bfa90f4e5c3ccb962fe"
    hash4       = "284120babcda473eb5137fb51ef741bfd8574e56ae3201dc50b2a3349b1da5fa"

  strings:
    $s1 = "function Scott /* U  */(accinp0 /* U  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* U  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* U  */ = (123, Turkey); return devel0 /* U  */;};" fullword ascii
    $s4 = "place = /* U  */(/* U  */\"noitisop\").split(''/* U  */).reverse(/* U  */).join('');" fullword ascii
    $s5 = "function Scott /* U  */(accinp0 /* U  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "DENMARK1 /* U  */= true;/* U  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}