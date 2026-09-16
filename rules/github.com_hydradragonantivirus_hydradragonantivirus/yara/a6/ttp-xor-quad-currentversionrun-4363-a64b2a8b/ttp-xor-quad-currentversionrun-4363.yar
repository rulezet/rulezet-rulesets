rule TTP_XOR_QUAD_CurrentVersionRun_4363 {
  strings:
    $key_4363 = { 10 0c [2] 34 02 [2] 1f 2e [2] 31 0c [2] 25 17 [2] 2a 0d [2] 34 10 [2] 36 11 [2] 2d 17 [2] 31 10 [2] 2d 3f }

  condition:
    any of them
}