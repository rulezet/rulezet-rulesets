rule TTP_XOR_QUAD_CurrentVersionRun_70c6 {
  strings:
    $key_70c6 = { 23 a9 [2] 07 a7 [2] 2c 8b [2] 02 a9 [2] 16 b2 [2] 19 a8 [2] 07 b5 [2] 05 b4 [2] 1e b2 [2] 02 b5 [2] 1e 9a }

  condition:
    any of them
}