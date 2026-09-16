rule TTP_XOR_QUAD_CurrentVersionRun_45c2 {
  strings:
    $key_45c2 = { 16 ad [2] 32 a3 [2] 19 8f [2] 37 ad [2] 23 b6 [2] 2c ac [2] 32 b1 [2] 30 b0 [2] 2b b6 [2] 37 b1 [2] 2b 9e }

  condition:
    any of them
}