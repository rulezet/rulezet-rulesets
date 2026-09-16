rule TTP_XOR_QUAD_CurrentVersionRun_3767 {
  strings:
    $key_3767 = { 64 08 [2] 40 06 [2] 6b 2a [2] 45 08 [2] 51 13 [2] 5e 09 [2] 40 14 [2] 42 15 [2] 59 13 [2] 45 14 [2] 59 3b }

  condition:
    any of them
}