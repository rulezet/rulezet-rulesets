rule TTP_XOR_QUAD_CurrentVersionRun_5eca {
  strings:
    $key_5eca = { 0d a5 [2] 29 ab [2] 02 87 [2] 2c a5 [2] 38 be [2] 37 a4 [2] 29 b9 [2] 2b b8 [2] 30 be [2] 2c b9 [2] 30 96 }

  condition:
    any of them
}