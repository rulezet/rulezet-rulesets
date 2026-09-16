rule TTP_XOR_QUAD_CurrentVersionRun_1c67 {
  strings:
    $key_1c67 = { 4f 08 [2] 6b 06 [2] 40 2a [2] 6e 08 [2] 7a 13 [2] 75 09 [2] 6b 14 [2] 69 15 [2] 72 13 [2] 6e 14 [2] 72 3b }

  condition:
    any of them
}