rule _20160921_9ed8ba5d12b4be06b54bbeb7c9325180_20160921_e6569e3fc498_2553 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"
    hash2       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = "turn \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"DYx\";})(),(" ascii
    $s2 = " f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz" ascii
    $s3 = "eturn \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})()," ascii
    $s4 = "(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s5 = "ction f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s6 = "\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(function f" ascii
    $s7 = "n f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"" ascii
    $s8 = "(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}