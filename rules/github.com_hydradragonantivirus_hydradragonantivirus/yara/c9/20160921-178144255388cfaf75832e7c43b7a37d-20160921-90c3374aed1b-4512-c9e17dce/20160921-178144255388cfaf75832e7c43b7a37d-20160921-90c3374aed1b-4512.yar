rule _20160921_178144255388cfaf75832e7c43b7a37d_20160921_90c3374aed1b_4512 {
  meta:
    description = "datamaliciousorder - from files 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_c459056d51b1a4ea3176139800021b35.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash2       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash3       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"
    hash4       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash5       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "n \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s2 = " f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s3 = "000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj" ascii
    $s4 = ";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f0" ascii
    $s5 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}