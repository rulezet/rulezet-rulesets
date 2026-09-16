rule TTP_XOR_QUAD_CurrentVersionRun_3347 {
  strings:
    $key_3347 = { 60 28 [2] 44 26 [2] 6f 0a [2] 41 28 [2] 55 33 [2] 5a 29 [2] 44 34 [2] 46 35 [2] 5d 33 [2] 41 34 [2] 5d 1b }

  condition:
    any of them
}