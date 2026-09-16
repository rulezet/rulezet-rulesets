rule _20160921_53ea150fd63a4ef657412c858a71a13e_20160921_86391eeb9293_3783 {
  meta:
    description = "datamaliciousorder - from files 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js, 20160921_e949fdc198fee477717395093f5853e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash2       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash3       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash4       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash5       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"
    hash6       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"
    hash7       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"

  strings:
    $s1 = "{return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(" ascii
    $s2 = "turn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})()" ascii
    $s3 = "ion f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s4 = "ction f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){retur" ascii
    $s5 = "u\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s6 = "ction f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}