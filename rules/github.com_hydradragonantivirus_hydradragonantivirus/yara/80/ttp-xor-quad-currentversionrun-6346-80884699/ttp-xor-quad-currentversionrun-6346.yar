rule TTP_XOR_QUAD_CurrentVersionRun_6346 {
  strings:
    $key_6346 = { 30 29 [2] 14 27 [2] 3f 0b [2] 11 29 [2] 05 32 [2] 0a 28 [2] 14 35 [2] 16 34 [2] 0d 32 [2] 11 35 [2] 0d 1a }

  condition:
    any of them
}