rule _20160921_9ed8ba5d12b4be06b54bbeb7c9325180_20160921_d999dcba53f5_5598 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj" ascii
    $s2 = "function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s3 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"X" ascii
    $s4 = "urn \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s5 = "),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}