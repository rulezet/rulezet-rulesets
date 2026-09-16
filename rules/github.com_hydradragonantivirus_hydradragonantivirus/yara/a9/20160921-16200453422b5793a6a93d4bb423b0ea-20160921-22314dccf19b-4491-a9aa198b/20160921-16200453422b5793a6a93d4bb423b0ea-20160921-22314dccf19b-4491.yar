rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_22314dccf19b_4491 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_5eea6af1c50b807f547cb710eb413110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash3       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"

  strings:
    $s1 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f0" ascii
    $s2 = " f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Y" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "n f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s5 = "rn \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}