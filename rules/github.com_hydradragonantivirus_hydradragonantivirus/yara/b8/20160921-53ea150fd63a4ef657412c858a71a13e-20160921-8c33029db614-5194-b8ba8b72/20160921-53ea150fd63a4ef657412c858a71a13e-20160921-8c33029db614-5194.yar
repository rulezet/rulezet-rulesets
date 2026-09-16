rule _20160921_53ea150fd63a4ef657412c858a71a13e_20160921_8c33029db614_5194 {
  meta:
    description = "datamaliciousorder - from files 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash2       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash3       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"
    hash4       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"

  strings:
    $s1 = "urn \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})()," ascii
    $s2 = "on f000(){return \"Qa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s3 = "nction f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s4 = "unction f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f000(){ret" ascii
    $s5 = "f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}