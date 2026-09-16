rule _20160517_8b61284936fd21d3d3f4ee04cecd7230_20160517_ead88b33a6cd_1263 {
  meta:
    description = "datamaliciousorder - from files 20160517_8b61284936fd21d3d3f4ee04cecd7230.js, 20160517_ead88b33a6cd639f00afa257f8686853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bbcd3ef714af607b8dddcede598012e59e3ef5a0f3174ec9aebd18489b70fb3"
    hash2       = "60d8df684b1c105a41fe4c9e5510e2cae29577391a9cf9edd4855ebe355b76ce"

  strings:
    $s1 = "function Scott /* W  */(accinp0 /* W  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* W  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* W  */ = (123, Turkey); return devel0 /* W  */;};" fullword ascii
    $s4 = "function Scott /* W  */(accinp0 /* W  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "place = /* W  */(/* W  */\"noitisop\").split(''/* W  */).reverse(/* W  */).join('');" fullword ascii
    $s6 = "DENMARK1 /* W  */= true;/* W  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}