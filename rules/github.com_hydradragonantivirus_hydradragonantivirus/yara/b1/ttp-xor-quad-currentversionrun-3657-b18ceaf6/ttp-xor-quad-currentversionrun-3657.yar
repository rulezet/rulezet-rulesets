rule TTP_XOR_QUAD_CurrentVersionRun_3657 {
  strings:
    $key_3657 = { 65 38 [2] 41 36 [2] 6a 1a [2] 44 38 [2] 50 23 [2] 5f 39 [2] 41 24 [2] 43 25 [2] 58 23 [2] 44 24 [2] 58 0b }

  condition:
    any of them
}