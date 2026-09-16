rule TTP_XOR_QUAD_CurrentVersionRun_1548 {
  strings:
    $key_1548 = { 46 27 [2] 62 29 [2] 49 05 [2] 67 27 [2] 73 3c [2] 7c 26 [2] 62 3b [2] 60 3a [2] 7b 3c [2] 67 3b [2] 7b 14 }

  condition:
    any of them
}