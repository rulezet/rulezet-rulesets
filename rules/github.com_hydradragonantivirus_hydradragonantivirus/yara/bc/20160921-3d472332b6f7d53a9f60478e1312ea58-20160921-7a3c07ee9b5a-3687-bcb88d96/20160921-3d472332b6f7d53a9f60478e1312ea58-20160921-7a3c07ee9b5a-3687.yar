rule _20160921_3d472332b6f7d53a9f60478e1312ea58_20160921_7a3c07ee9b5a_3687 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"

  strings:
    $s1 = "ction f000(){return \"KXg\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s2 = " \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s3 = ",(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Tn\";})(),(function f000(){" ascii
    $s4 = " \"HJm\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(fu" ascii
    $s5 = "000(){return \"Nv\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\"" ascii
    $s6 = ")(),(function f000(){return \"HJm\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"SGs\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}