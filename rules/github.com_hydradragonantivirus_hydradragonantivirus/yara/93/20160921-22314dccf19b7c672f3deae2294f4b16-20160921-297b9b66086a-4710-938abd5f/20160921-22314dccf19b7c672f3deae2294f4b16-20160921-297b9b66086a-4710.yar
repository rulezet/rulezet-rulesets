rule _20160921_22314dccf19b7c672f3deae2294f4b16_20160921_297b9b66086a_4710 {
  meta:
    description = "datamaliciousorder - from files 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_b4c84c92954782bcf19013150a359ec6.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash2       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash3       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash4       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash5       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"
    hash6       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash7       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"

  strings:
    $s1 = "})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000" ascii
    $s2 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s3 = "turn \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s4 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s5 = "})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}