rule TTP_XOR_QUAD_CurrentVersionRun_4479 {
  strings:
    $key_4479 = { 17 16 [2] 33 18 [2] 18 34 [2] 36 16 [2] 22 0d [2] 2d 17 [2] 33 0a [2] 31 0b [2] 2a 0d [2] 36 0a [2] 2a 25 }

  condition:
    any of them
}