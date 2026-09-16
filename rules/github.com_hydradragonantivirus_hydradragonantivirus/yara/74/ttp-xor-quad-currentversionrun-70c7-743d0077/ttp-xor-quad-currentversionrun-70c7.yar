rule TTP_XOR_QUAD_CurrentVersionRun_70c7 {
  strings:
    $key_70c7 = { 23 a8 [2] 07 a6 [2] 2c 8a [2] 02 a8 [2] 16 b3 [2] 19 a9 [2] 07 b4 [2] 05 b5 [2] 1e b3 [2] 02 b4 [2] 1e 9b }

  condition:
    any of them
}