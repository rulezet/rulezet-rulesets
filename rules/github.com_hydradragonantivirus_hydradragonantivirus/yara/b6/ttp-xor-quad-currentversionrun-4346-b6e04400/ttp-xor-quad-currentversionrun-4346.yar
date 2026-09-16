rule TTP_XOR_QUAD_CurrentVersionRun_4346 {
  strings:
    $key_4346 = { 10 29 [2] 34 27 [2] 1f 0b [2] 31 29 [2] 25 32 [2] 2a 28 [2] 34 35 [2] 36 34 [2] 2d 32 [2] 31 35 [2] 2d 1a }

  condition:
    any of them
}