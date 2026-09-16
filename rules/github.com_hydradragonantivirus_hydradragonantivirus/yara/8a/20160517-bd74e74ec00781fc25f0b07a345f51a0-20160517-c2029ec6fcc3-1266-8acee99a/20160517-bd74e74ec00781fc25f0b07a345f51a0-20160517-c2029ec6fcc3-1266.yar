rule _20160517_bd74e74ec00781fc25f0b07a345f51a0_20160517_c2029ec6fcc3_1266 {
  meta:
    description = "datamaliciousorder - from files 20160517_bd74e74ec00781fc25f0b07a345f51a0.js, 20160517_c2029ec6fcc33c6c897b5e79f77220a8.js, 20160517_f35f3a9a8b7bc4f195d57ef1f19d1d33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d9a038cef529ef390186d121ed715e27d5c7319670dde98066c79a55bad2200"
    hash2       = "c2f30e4750ab8ea6845308cdcb3f1cf888a6d7d13b98405ead47a42ad6de81ac"
    hash3       = "3cdd25c7da7a40364dc785aa8389485a2bceb6fa5e9755a8374587cfe629d13b"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* H  */, Currency, (true, false));" fullword ascii
    $s2 = "function Scott /* H  */(accinp0 /* H  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* H  */ = (123, Turkey); return devel0 /* H  */;};" fullword ascii
    $s4 = "DENMARK1 /* H  */= true;/* H  */" fullword ascii
    $s5 = "function Scott /* H  */(accinp0 /* H  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "place = /* H  */(/* H  */\"noitisop\").split(''/* H  */).reverse(/* H  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}