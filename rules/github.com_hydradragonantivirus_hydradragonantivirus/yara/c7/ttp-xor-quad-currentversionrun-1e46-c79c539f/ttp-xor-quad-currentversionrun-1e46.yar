rule TTP_XOR_QUAD_CurrentVersionRun_1e46 {
  strings:
    $key_1e46 = { 4d 29 [2] 69 27 [2] 42 0b [2] 6c 29 [2] 78 32 [2] 77 28 [2] 69 35 [2] 6b 34 [2] 70 32 [2] 6c 35 [2] 70 1a }

  condition:
    any of them
}