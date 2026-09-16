rule TTP_XOR_QUAD_CurrentVersionRun_e767 {
  strings:
    $key_e767 = { b4 08 [2] 90 06 [2] bb 2a [2] 95 08 [2] 81 13 [2] 8e 09 [2] 90 14 [2] 92 15 [2] 89 13 [2] 95 14 [2] 89 3b }

  condition:
    any of them
}