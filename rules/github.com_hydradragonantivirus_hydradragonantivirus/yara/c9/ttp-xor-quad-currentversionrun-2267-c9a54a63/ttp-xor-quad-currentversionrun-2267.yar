rule TTP_XOR_QUAD_CurrentVersionRun_2267 {
  strings:
    $key_2267 = { 71 08 [2] 55 06 [2] 7e 2a [2] 50 08 [2] 44 13 [2] 4b 09 [2] 55 14 [2] 57 15 [2] 4c 13 [2] 50 14 [2] 4c 3b }

  condition:
    any of them
}