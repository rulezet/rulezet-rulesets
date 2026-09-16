rule TTP_XOR_QUAD_CurrentVersionRun_1346 {
  strings:
    $key_1346 = { 40 29 [2] 64 27 [2] 4f 0b [2] 61 29 [2] 75 32 [2] 7a 28 [2] 64 35 [2] 66 34 [2] 7d 32 [2] 61 35 [2] 7d 1a }

  condition:
    any of them
}