rule _20160517_5dddbc5b84e3507a449d55a6ad821800_20160517_753b2107702d_1257 {
  meta:
    description = "datamaliciousorder - from files 20160517_5dddbc5b84e3507a449d55a6ad821800.js, 20160517_753b2107702dce2f497bc7072b2982bc.js, 20160517_9e6e5e013548d4a90fd0b553c4b5b4a1.js, 20160517_e7ebe13cda2abc920d52810e17f08f78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5ab063c8b9a908f60638820d796e8365f40f05c27cb705d17f8e95c1349941b"
    hash2       = "00084fe498de70ceae0623fe536bdb28399bfbd222410bb9bebef45814396009"
    hash3       = "c665d2725ba7599bc3cc7d833975254ad71be374628d1ea05b43747521a3e72c"
    hash4       = "f2884aaee0fb495cc2539ae65479ab85cc3b554884fe41cc4ccc669c042bbfcf"

  strings:
    $s1 = "function Scott /* M  */(accinp0 /* M  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* M  */ = (123, Turkey); return devel0 /* M  */;};" fullword ascii
    $s3 = "devel1[aaa](Turkey0 /* M  */, Currency, (true, false));" fullword ascii
    $s4 = "DENMARK1 /* M  */= true;/* M  */" fullword ascii
    $s5 = "function Scott /* M  */(accinp0 /* M  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "place = /* M  */(/* M  */\"noitisop\").split(''/* M  */).reverse(/* M  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}