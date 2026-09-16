rule _20160517_0587aa576734d49c02121d3d0d0aa175_20160517_1b06ffa41e55_1230 {
  meta:
    description = "datamaliciousorder - from files 20160517_0587aa576734d49c02121d3d0d0aa175.js, 20160517_1b06ffa41e55c001f34d08041d2d64cf.js, 20160517_a8f041fb26074ea3c89992aba31ed070.js, 20160517_fc74e3aba914c1856fae34338211db13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05adf5b712aefa4bbff00eda85eaa14ba5e43847fe98c45efbad27c438a6373b"
    hash2       = "d0ca64b776daa8634ca505f892e2a7f195eeefa6bc44128b4f84a116d67ea406"
    hash3       = "2404d5b0acb2a4e95c9520bdcfa96288b24d57552f92e84026c1236cc2ef892d"
    hash4       = "cbad1e73a5826ced49b7d95d02ce558b329b71ed51c8f627bbcb261fa5db4a14"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* k  */ = (123, Turkey); return devel0 /* k  */;};" fullword ascii
    $s2 = "function Scott /* k  */(accinp0 /* k  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "devel1[aaa](Turkey0 /* k  */, Currency, (true, false));" fullword ascii
    $s4 = "function Scott /* k  */(accinp0 /* k  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "DENMARK1 /* k  */= true;/* k  */" fullword ascii
    $s6 = "place = /* k  */(/* k  */\"noitisop\").split(''/* k  */).reverse(/* k  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}