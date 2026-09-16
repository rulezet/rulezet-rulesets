rule TTP_XOR_QUAD_CurrentVersionRun_4436 {
  strings:
    $key_4436 = { 17 59 [2] 33 57 [2] 18 7b [2] 36 59 [2] 22 42 [2] 2d 58 [2] 33 45 [2] 31 44 [2] 2a 42 [2] 36 45 [2] 2a 6a }

  condition:
    any of them
}