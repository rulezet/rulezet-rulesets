rule TTP_XOR_QUAD_CurrentVersionRun_42da {
  strings:
    $key_42da = { 11 b5 [2] 35 bb [2] 1e 97 [2] 30 b5 [2] 24 ae [2] 2b b4 [2] 35 a9 [2] 37 a8 [2] 2c ae [2] 30 a9 [2] 2c 86 }

  condition:
    any of them
}