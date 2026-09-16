rule TTP_XOR_QUAD_CurrentVersionRun_70d6 {
  strings:
    $key_70d6 = { 23 b9 [2] 07 b7 [2] 2c 9b [2] 02 b9 [2] 16 a2 [2] 19 b8 [2] 07 a5 [2] 05 a4 [2] 1e a2 [2] 02 a5 [2] 1e 8a }

  condition:
    any of them
}