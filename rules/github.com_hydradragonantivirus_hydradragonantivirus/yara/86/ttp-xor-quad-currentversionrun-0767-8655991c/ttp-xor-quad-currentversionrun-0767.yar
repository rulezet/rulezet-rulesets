rule TTP_XOR_QUAD_CurrentVersionRun_0767 {
  strings:
    $key_0767 = { 54 08 [2] 70 06 [2] 5b 2a [2] 75 08 [2] 61 13 [2] 6e 09 [2] 70 14 [2] 72 15 [2] 69 13 [2] 75 14 [2] 69 3b }

  condition:
    any of them
}