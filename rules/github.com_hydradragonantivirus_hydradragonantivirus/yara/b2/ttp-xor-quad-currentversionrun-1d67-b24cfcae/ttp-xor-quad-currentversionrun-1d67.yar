rule TTP_XOR_QUAD_CurrentVersionRun_1d67 {
  strings:
    $key_1d67 = { 4e 08 [2] 6a 06 [2] 41 2a [2] 6f 08 [2] 7b 13 [2] 74 09 [2] 6a 14 [2] 68 15 [2] 73 13 [2] 6f 14 [2] 73 3b }

  condition:
    any of them
}