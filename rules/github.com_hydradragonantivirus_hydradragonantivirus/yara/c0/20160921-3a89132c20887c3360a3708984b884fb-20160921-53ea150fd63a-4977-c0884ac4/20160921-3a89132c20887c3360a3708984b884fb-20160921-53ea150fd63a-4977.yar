rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_53ea150fd63a_4977 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash3       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash4       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"

  strings:
    $s1 = "urn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s2 = "(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";}" ascii
    $s3 = "Ux\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function" ascii
    $s4 = "eturn \"TKp\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s5 = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"MMz\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}