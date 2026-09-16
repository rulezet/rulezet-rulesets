rule TTP_XOR_QUAD_CurrentVersionRun_5b36 {
  strings:
    $key_5b36 = { 08 59 [2] 2c 57 [2] 07 7b [2] 29 59 [2] 3d 42 [2] 32 58 [2] 2c 45 [2] 2e 44 [2] 35 42 [2] 29 45 [2] 35 6a }

  condition:
    any of them
}