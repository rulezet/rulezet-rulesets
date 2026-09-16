rule TTP_XOR_QUAD_CurrentVersionRun_e877 {
  strings:
    $key_e877 = { bb 18 [2] 9f 16 [2] b4 3a [2] 9a 18 [2] 8e 03 [2] 81 19 [2] 9f 04 [2] 9d 05 [2] 86 03 [2] 9a 04 [2] 86 2b }

  condition:
    any of them
}