rule TTP_XOR_QUAD_CurrentVersionRun_4379 {
  strings:
    $key_4379 = { 10 16 [2] 34 18 [2] 1f 34 [2] 31 16 [2] 25 0d [2] 2a 17 [2] 34 0a [2] 36 0b [2] 2d 0d [2] 31 0a [2] 2d 25 }

  condition:
    any of them
}