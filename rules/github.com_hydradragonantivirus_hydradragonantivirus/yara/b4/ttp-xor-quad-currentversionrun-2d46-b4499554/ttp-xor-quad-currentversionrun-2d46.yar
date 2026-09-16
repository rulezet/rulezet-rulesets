rule TTP_XOR_QUAD_CurrentVersionRun_2d46 {
  strings:
    $key_2d46 = { 7e 29 [2] 5a 27 [2] 71 0b [2] 5f 29 [2] 4b 32 [2] 44 28 [2] 5a 35 [2] 58 34 [2] 43 32 [2] 5f 35 [2] 43 1a }

  condition:
    any of them
}