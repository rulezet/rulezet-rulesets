rule TTP_XOR_QUAD_CurrentVersionRun_70c3 {
  strings:
    $key_70c3 = { 23 ac [2] 07 a2 [2] 2c 8e [2] 02 ac [2] 16 b7 [2] 19 ad [2] 07 b0 [2] 05 b1 [2] 1e b7 [2] 02 b0 [2] 1e 9f }

  condition:
    any of them
}