rule _20160921_0d3dee472bd7a0a1e2c48044e2c47f0b_20160921_22314dccf19b_3329 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_b4c84c92954782bcf19013150a359ec6.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash2       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash3       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash4       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"
    hash5       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1 = "(){return \"ZIi\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";" ascii
    $s2 = "i\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s3 = "rn \"Qa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s4 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";}" ascii
    $s5 = " \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s6 = "{return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DIa\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}