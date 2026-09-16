rule _20160921_178144255388cfaf75832e7c43b7a37d_20160921_90c3374aed1b_4515 {
  meta:
    description = "datamaliciousorder - from files 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash2       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash3       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash4       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"
    hash5       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "turn \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(" ascii
    $s2 = "on f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s3 = "00(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";" ascii
    $s4 = "eturn \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5 = "nction f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}