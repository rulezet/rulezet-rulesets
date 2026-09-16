rule _20160517_797a4d36802f4efd758895c36df4e120_20160517_c1021629cb92_1261 {
  meta:
    description = "datamaliciousorder - from files 20160517_797a4d36802f4efd758895c36df4e120.js, 20160517_c1021629cb92f92e46f3e215cadabab0.js, 20160517_d321170f8d34939bbc56dad85c7f3dae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f256efd2938e033cf5545c37a7d63ebec1a2c403ec28da79aab7345a3872bb15"
    hash2       = "641d542e4fbc6c44151953d21e5d05beb92ec6ae2fa5a6373ec09e717306e0b1"
    hash3       = "be9e0dac682d4562fb93e109bc2496db7084d46104f5effec31806eb242bf097"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* n  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* n  */ = (123, Turkey); return devel0 /* n  */;};" fullword ascii
    $s3 = "function Scott /* n  */(accinp0 /* n  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "place = /* n  */(/* n  */\"noitisop\").split(''/* n  */).reverse(/* n  */).join('');" fullword ascii
    $s5 = "function Scott /* n  */(accinp0 /* n  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "DENMARK1 /* n  */= true;/* n  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}