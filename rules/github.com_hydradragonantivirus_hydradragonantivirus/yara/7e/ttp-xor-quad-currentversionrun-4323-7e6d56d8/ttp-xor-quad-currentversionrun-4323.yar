rule TTP_XOR_QUAD_CurrentVersionRun_4323 {
  strings:
    $key_4323 = { 10 4c [2] 34 42 [2] 1f 6e [2] 31 4c [2] 25 57 [2] 2a 4d [2] 34 50 [2] 36 51 [2] 2d 57 [2] 31 50 [2] 2d 7f }

  condition:
    any of them
}