rule _20160517_8d7659ed3324d4fa2daef1dd98a36f93_20160517_8ec0671da03c_1264 {
  meta:
    description = "datamaliciousorder - from files 20160517_8d7659ed3324d4fa2daef1dd98a36f93.js, 20160517_8ec0671da03c83955bda3b3a4c83eadd.js, 20160517_96babcf93d965633328c6c4c69e52156.js, 20160517_f724a523401313ccc078a9efb217404a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9073b76b44b6c26bdb84a847f27b8b69758912ba63f269c3c11da08ad20cf95"
    hash2       = "efb19533287b4c822556ebffd4d3ebd934d6427f0e342ef4b813d11d79252d19"
    hash3       = "754f06d1e2df40e26d2c26c03ba9230a377e6c67b558984631e7a8e2b4b050bf"
    hash4       = "79342b666e7795c3e3afd0d031fa34f1091eb399595939b3072cb2cf29088937"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* J  */ = (123, Turkey); return devel0 /* J  */;};" fullword ascii
    $s2 = "function Scott /* J  */(accinp0 /* J  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "devel1[aaa](Turkey0 /* J  */, Currency, (true, false));" fullword ascii
    $s4 = "place = /* J  */(/* J  */\"noitisop\").split(''/* J  */).reverse(/* J  */).join('');" fullword ascii
    $s5 = "function Scott /* J  */(accinp0 /* J  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "DENMARK1 /* J  */= true;/* J  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}