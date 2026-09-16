rule TTP_XOR_QUAD_CurrentVersionRun_5767 {
  strings:
    $key_5767 = { 04 08 [2] 20 06 [2] 0b 2a [2] 25 08 [2] 31 13 [2] 3e 09 [2] 20 14 [2] 22 15 [2] 39 13 [2] 25 14 [2] 39 3b }

  condition:
    any of them
}