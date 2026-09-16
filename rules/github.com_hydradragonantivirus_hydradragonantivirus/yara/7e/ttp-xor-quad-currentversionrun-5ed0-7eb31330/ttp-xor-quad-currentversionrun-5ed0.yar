rule TTP_XOR_QUAD_CurrentVersionRun_5ed0 {
  strings:
    $key_5ed0 = { 0d bf [2] 29 b1 [2] 02 9d [2] 2c bf [2] 38 a4 [2] 37 be [2] 29 a3 [2] 2b a2 [2] 30 a4 [2] 2c a3 [2] 30 8c }

  condition:
    any of them
}