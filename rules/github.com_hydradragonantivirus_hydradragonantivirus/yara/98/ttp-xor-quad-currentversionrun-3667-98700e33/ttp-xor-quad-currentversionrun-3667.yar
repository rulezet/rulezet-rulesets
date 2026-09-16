rule TTP_XOR_QUAD_CurrentVersionRun_3667 {
  strings:
    $key_3667 = { 65 08 [2] 41 06 [2] 6a 2a [2] 44 08 [2] 50 13 [2] 5f 09 [2] 41 14 [2] 43 15 [2] 58 13 [2] 44 14 [2] 58 3b }

  condition:
    any of them
}