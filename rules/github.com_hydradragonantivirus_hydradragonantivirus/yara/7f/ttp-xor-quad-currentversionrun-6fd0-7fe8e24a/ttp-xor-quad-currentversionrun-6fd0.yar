rule TTP_XOR_QUAD_CurrentVersionRun_6fd0 {
  strings:
    $key_6fd0 = { 3c bf [2] 18 b1 [2] 33 9d [2] 1d bf [2] 09 a4 [2] 06 be [2] 18 a3 [2] 1a a2 [2] 01 a4 [2] 1d a3 [2] 01 8c }

  condition:
    any of them
}