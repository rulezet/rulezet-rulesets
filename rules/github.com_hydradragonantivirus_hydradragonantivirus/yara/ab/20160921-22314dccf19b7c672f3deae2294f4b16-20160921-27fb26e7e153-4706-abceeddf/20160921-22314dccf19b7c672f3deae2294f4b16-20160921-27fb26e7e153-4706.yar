rule _20160921_22314dccf19b7c672f3deae2294f4b16_20160921_27fb26e7e153_4706 {
  meta:
    description = "datamaliciousorder - from files 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash2       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash3       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1 = "n f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"G" ascii
    $s2 = "(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";" ascii
    $s3 = "nction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii
    $s4 = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s5 = "n \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}