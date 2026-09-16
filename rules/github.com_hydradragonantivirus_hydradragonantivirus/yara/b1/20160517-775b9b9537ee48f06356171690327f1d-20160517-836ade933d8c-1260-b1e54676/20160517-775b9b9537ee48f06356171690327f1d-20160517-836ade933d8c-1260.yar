rule _20160517_775b9b9537ee48f06356171690327f1d_20160517_836ade933d8c_1260 {
  meta:
    description = "datamaliciousorder - from files 20160517_775b9b9537ee48f06356171690327f1d.js, 20160517_836ade933d8cf3900c743164655fd968.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "568815beb83a47858cf00fd72f6bf462c24293c8899fe342dcd1c576f725d2e9"
    hash2       = "b9e0b8b98efb480900421e81f1ca30ab851fbe04755c018afe4b232d63bbb71b"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* A  */ = (123, Turkey); return devel0 /* A  */;};" fullword ascii
    $s2 = "function Scott /* A  */(accinp0 /* A  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "devel1[aaa](Turkey0 /* A  */, Currency, (true, false));" fullword ascii
    $s4 = "DENMARK1 /* A  */= true;/* A  */" fullword ascii
    $s5 = "function Scott /* A  */(accinp0 /* A  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "place = /* A  */(/* A  */\"noitisop\").split(''/* A  */).reverse(/* A  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}