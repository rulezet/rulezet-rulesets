rule TTP_XOR_QUAD_CurrentVersionRun_45c1 {
  strings:
    $key_45c1 = { 16 ae [2] 32 a0 [2] 19 8c [2] 37 ae [2] 23 b5 [2] 2c af [2] 32 b2 [2] 30 b3 [2] 2b b5 [2] 37 b2 [2] 2b 9d }

  condition:
    any of them
}