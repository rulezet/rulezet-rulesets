rule TTP_XOR_QUAD_CurrentVersionRun_6637 {
  strings:
    $key_6637 = { 35 58 [2] 11 56 [2] 3a 7a [2] 14 58 [2] 00 43 [2] 0f 59 [2] 11 44 [2] 13 45 [2] 08 43 [2] 14 44 [2] 08 6b }

  condition:
    any of them
}