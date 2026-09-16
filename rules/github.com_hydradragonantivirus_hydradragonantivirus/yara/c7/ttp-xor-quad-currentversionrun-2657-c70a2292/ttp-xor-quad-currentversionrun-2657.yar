rule TTP_XOR_QUAD_CurrentVersionRun_2657 {
  strings:
    $key_2657 = { 75 38 [2] 51 36 [2] 7a 1a [2] 54 38 [2] 40 23 [2] 4f 39 [2] 51 24 [2] 53 25 [2] 48 23 [2] 54 24 [2] 48 0b }

  condition:
    any of them
}