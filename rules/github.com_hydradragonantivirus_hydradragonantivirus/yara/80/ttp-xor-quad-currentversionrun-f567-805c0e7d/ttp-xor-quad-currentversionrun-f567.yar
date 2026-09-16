rule TTP_XOR_QUAD_CurrentVersionRun_f567 {
  strings:
    $key_f567 = { a6 08 [2] 82 06 [2] a9 2a [2] 87 08 [2] 93 13 [2] 9c 09 [2] 82 14 [2] 80 15 [2] 9b 13 [2] 87 14 [2] 9b 3b }

  condition:
    any of them
}