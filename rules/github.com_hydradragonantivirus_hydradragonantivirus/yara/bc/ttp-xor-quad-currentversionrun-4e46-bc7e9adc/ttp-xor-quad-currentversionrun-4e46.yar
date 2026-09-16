rule TTP_XOR_QUAD_CurrentVersionRun_4e46 {
  strings:
    $key_4e46 = { 1d 29 [2] 39 27 [2] 12 0b [2] 3c 29 [2] 28 32 [2] 27 28 [2] 39 35 [2] 3b 34 [2] 20 32 [2] 3c 35 [2] 20 1a }

  condition:
    any of them
}