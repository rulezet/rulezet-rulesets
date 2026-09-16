rule TTP_XOR_QUAD_CurrentVersionRun_1d46 {
  strings:
    $key_1d46 = { 4e 29 [2] 6a 27 [2] 41 0b [2] 6f 29 [2] 7b 32 [2] 74 28 [2] 6a 35 [2] 68 34 [2] 73 32 [2] 6f 35 [2] 73 1a }

  condition:
    any of them
}