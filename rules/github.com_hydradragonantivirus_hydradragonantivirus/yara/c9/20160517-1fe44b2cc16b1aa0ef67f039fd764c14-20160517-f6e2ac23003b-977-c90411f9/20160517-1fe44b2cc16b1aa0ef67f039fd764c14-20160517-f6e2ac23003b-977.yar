rule _20160517_1fe44b2cc16b1aa0ef67f039fd764c14_20160517_f6e2ac23003b_977 {
  meta:
    description = "datamaliciousorder - from files 20160517_1fe44b2cc16b1aa0ef67f039fd764c14.js, 20160517_f6e2ac23003b14bf9e8985fa4371cfbc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0f835e131e1a921ca839d9123e2c728e705a5be960b1732505997b1be8a8c95"
    hash2       = "bd75be6cb27c5cd2fefcef1b225c1ec9363b89911743225336f0f9bf64eaee38"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* VR  */, Currency, (true, false));" fullword ascii
    $s2 = "function Scott /* VR  */(accinp0 /* VR  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* VR  */ = (123, Turkey); return devel0 /* VR  */;};" fullword ascii
    $s4 = "place = /* VR  */(/* VR  */\"noitisop\").split(''/* VR  */).reverse(/* VR  */).join('');" fullword ascii
    $s5 = "DENMARK1 /* VR  */= true;/* VR  */" fullword ascii
    $s6 = "function Scott /* VR  */(accinp0 /* VR  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}