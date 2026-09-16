rule TTP_XOR_QUAD_CurrentVersionRun_3157 {
  strings:
    $key_3157 = { 62 38 [2] 46 36 [2] 6d 1a [2] 43 38 [2] 57 23 [2] 58 39 [2] 46 24 [2] 44 25 [2] 5f 23 [2] 43 24 [2] 5f 0b }

  condition:
    any of them
}