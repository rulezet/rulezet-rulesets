rule TTP_XOR_QUAD_CurrentVersionRun_1448 {
  strings:
    $key_1448 = { 47 27 [2] 63 29 [2] 48 05 [2] 66 27 [2] 72 3c [2] 7d 26 [2] 63 3b [2] 61 3a [2] 7a 3c [2] 66 3b [2] 7a 14 }

  condition:
    any of them
}