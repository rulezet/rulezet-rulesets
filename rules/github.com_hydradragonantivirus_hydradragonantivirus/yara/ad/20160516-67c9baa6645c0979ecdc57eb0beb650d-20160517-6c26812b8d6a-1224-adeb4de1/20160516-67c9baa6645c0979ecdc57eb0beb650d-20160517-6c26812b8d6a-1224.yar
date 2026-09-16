rule _20160516_67c9baa6645c0979ecdc57eb0beb650d_20160517_6c26812b8d6a_1224 {
  meta:
    description = "datamaliciousorder - from files 20160516_67c9baa6645c0979ecdc57eb0beb650d.js, 20160517_6c26812b8d6afb82369120adf22b8b64.js, 20160517_dde147cd77b1bd2575b7c9736b81d83d.js, 20160517_ec1e65f8c9c4ddbb1ccd257214d0d792.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70a49ea35334bc162628f832a304cd327a1d2ca63e6b1457c79e1d95f033363d"
    hash2       = "525a403d946838880ba7d1a8026a4014d680b971d72836e0b77e26d98afc388f"
    hash3       = "d99aebbefd60ec2bd7d6ba58aba6519a6318788b89deb6469a47ff3e525cc48c"
    hash4       = "ea19d7de8b370d50370ae68abbc5f53efbc88afcba41de204ab358d93039906b"

  strings:
    $s1 = "function Scott /* O  */(accinp0 /* O  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* O  */ = (123, Turkey); return devel0 /* O  */;};" fullword ascii
    $s3 = "devel1[aaa](Turkey0 /* O  */, Currency, (true, false));" fullword ascii
    $s4 = "place = /* O  */(/* O  */\"noitisop\").split(''/* O  */).reverse(/* O  */).join('');" fullword ascii
    $s5 = "DENMARK1 /* O  */= true;/* O  */" fullword ascii
    $s6 = "function Scott /* O  */(accinp0 /* O  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}