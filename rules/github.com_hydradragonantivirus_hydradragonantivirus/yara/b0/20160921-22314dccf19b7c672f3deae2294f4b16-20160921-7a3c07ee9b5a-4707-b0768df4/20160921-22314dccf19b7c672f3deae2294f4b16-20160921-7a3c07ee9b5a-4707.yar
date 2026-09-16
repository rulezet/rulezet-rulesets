rule _20160921_22314dccf19b7c672f3deae2294f4b16_20160921_7a3c07ee9b5a_4707 {
  meta:
    description = "datamaliciousorder - from files 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"

  strings:
    $s1 = "\"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(funct" ascii
    $s2 = "(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s3 = "){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})" ascii
    $s4 = " f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl" ascii
    $s5 = "urn \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"QDg\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}