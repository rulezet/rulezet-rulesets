rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_53ea150fd63a_3738 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash3       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash4       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"

  strings:
    $s1 = "00(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj" ascii
    $s2 = "ction f000(){return \"ZFe\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s3 = "urn \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s4 = "n \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s5 = "function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f000(){re" ascii
    $s6 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}