rule TTP_XOR_QUAD_CurrentVersionRun_6037 {
  strings:
    $key_6037 = { 33 58 [2] 17 56 [2] 3c 7a [2] 12 58 [2] 06 43 [2] 09 59 [2] 17 44 [2] 15 45 [2] 0e 43 [2] 12 44 [2] 0e 6b }

  condition:
    any of them
}