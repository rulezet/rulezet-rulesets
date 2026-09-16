rule TTP_XOR_QUAD_CurrentVersionRun_3fd0 {
  strings:
    $key_3fd0 = { 6c bf [2] 48 b1 [2] 63 9d [2] 4d bf [2] 59 a4 [2] 56 be [2] 48 a3 [2] 4a a2 [2] 51 a4 [2] 4d a3 [2] 51 8c }

  condition:
    any of them
}