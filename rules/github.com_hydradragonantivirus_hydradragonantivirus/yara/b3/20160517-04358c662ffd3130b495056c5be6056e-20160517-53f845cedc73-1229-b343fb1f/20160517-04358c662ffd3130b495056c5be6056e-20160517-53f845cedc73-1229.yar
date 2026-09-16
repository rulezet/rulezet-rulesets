rule _20160517_04358c662ffd3130b495056c5be6056e_20160517_53f845cedc73_1229 {
  meta:
    description = "datamaliciousorder - from files 20160517_04358c662ffd3130b495056c5be6056e.js, 20160517_53f845cedc73557370fb7a49f72ecfa1.js, 20160517_a980bda728182e2acbf098e1c4ebacb1.js, 20160517_e817d7510b74f7ec380819a0d5b9c921.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2588a31bcb486a146cc3761e353738767da7318538f5437e8012afca33bc8776"
    hash2       = "ae6e818ab5503698d8c7f68ca1b65d4079b930168a0abdca7f64ae8e89721cab"
    hash3       = "5e35be43c02ab29bb955a9f3367c07f79aef31b64f614765ebe2a2ec575d82d8"
    hash4       = "2bba6c22a39e262dffb0ed57699040d4230ff4c433ac454a7615997248949515"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* c  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* c  */ = (123, Turkey); return devel0 /* c  */;};" fullword ascii
    $s3 = "function Scott /* c  */(accinp0 /* c  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "DENMARK1 /* c  */= true;/* c  */" fullword ascii
    $s5 = "place = /* c  */(/* c  */\"noitisop\").split(''/* c  */).reverse(/* c  */).join('');" fullword ascii
    $s6 = "function Scott /* c  */(accinp0 /* c  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}