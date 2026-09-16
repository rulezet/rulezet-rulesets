rule TTP_XOR_QUAD_CurrentVersionRun_7ed0 {
  strings:
    $key_7ed0 = { 2d bf [2] 09 b1 [2] 22 9d [2] 0c bf [2] 18 a4 [2] 17 be [2] 09 a3 [2] 0b a2 [2] 10 a4 [2] 0c a3 [2] 10 8c }

  condition:
    any of them
}