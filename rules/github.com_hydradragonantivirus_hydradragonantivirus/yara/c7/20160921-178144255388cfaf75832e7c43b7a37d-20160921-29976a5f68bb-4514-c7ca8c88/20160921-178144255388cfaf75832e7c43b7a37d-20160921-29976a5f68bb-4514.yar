rule _20160921_178144255388cfaf75832e7c43b7a37d_20160921_29976a5f68bb_4514 {
  meta:
    description = "datamaliciousorder - from files 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js, 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_d69f5159aadd1440760083d8952604c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash2       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash3       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"
    hash4       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash5       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"

  strings:
    $s1 = "n \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s2 = ")(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000()" ascii
    $s3 = "000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl" ascii
    $s4 = "WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(functi" ascii
    $s5 = "on f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}