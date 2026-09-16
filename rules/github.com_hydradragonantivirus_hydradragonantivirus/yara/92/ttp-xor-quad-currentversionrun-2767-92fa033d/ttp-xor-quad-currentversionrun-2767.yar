rule TTP_XOR_QUAD_CurrentVersionRun_2767 {
  strings:
    $key_2767 = { 74 08 [2] 50 06 [2] 7b 2a [2] 55 08 [2] 41 13 [2] 4e 09 [2] 50 14 [2] 52 15 [2] 49 13 [2] 55 14 [2] 49 3b }

  condition:
    any of them
}