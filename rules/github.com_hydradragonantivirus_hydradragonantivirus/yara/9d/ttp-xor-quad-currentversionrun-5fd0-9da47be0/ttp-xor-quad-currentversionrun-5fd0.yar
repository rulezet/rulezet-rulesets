rule TTP_XOR_QUAD_CurrentVersionRun_5fd0 {
  strings:
    $key_5fd0 = { 0c bf [2] 28 b1 [2] 03 9d [2] 2d bf [2] 39 a4 [2] 36 be [2] 28 a3 [2] 2a a2 [2] 31 a4 [2] 2d a3 [2] 31 8c }

  condition:
    any of them
}