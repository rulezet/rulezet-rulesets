rule TTP_XOR_QUAD_CurrentVersionRun_4d46 {
  strings:
    $key_4d46 = { 1e 29 [2] 3a 27 [2] 11 0b [2] 3f 29 [2] 2b 32 [2] 24 28 [2] 3a 35 [2] 38 34 [2] 23 32 [2] 3f 35 [2] 23 1a }

  condition:
    any of them
}