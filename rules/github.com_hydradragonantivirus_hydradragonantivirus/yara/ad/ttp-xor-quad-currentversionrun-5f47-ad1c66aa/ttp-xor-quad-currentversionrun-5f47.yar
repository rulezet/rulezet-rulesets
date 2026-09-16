rule TTP_XOR_QUAD_CurrentVersionRun_5f47 {
  strings:
    $key_5f47 = { 0c 28 [2] 28 26 [2] 03 0a [2] 2d 28 [2] 39 33 [2] 36 29 [2] 28 34 [2] 2a 35 [2] 31 33 [2] 2d 34 [2] 31 1b }

  condition:
    any of them
}