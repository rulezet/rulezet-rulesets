rule TTP_XOR_QUAD_CurrentVersionRun_3357 {
  strings:
    $key_3357 = { 60 38 [2] 44 36 [2] 6f 1a [2] 41 38 [2] 55 23 [2] 5a 39 [2] 44 24 [2] 46 25 [2] 5d 23 [2] 41 24 [2] 5d 0b }

  condition:
    any of them
}