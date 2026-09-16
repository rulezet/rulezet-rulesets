rule TTP_XOR_QUAD_CurrentVersionRun_6c46 {
  strings:
    $key_6c46 = { 3f 29 [2] 1b 27 [2] 30 0b [2] 1e 29 [2] 0a 32 [2] 05 28 [2] 1b 35 [2] 19 34 [2] 02 32 [2] 1e 35 [2] 02 1a }

  condition:
    any of them
}