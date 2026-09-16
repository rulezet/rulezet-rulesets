rule TTP_XOR_QUAD_CurrentVersionRun_4457 {
  strings:
    $key_4457 = { 17 38 [2] 33 36 [2] 18 1a [2] 36 38 [2] 22 23 [2] 2d 39 [2] 33 24 [2] 31 25 [2] 2a 23 [2] 36 24 [2] 2a 0b }

  condition:
    any of them
}