rule TTP_XOR_QUAD_CurrentVersionRun_4657 {
  strings:
    $key_4657 = { 15 38 [2] 31 36 [2] 1a 1a [2] 34 38 [2] 20 23 [2] 2f 39 [2] 31 24 [2] 33 25 [2] 28 23 [2] 34 24 [2] 28 0b }

  condition:
    any of them
}