rule TTP_XOR_QUAD_CurrentVersionRun_f4d1 {
  strings:
    $key_f4d1 = { a7 be [2] 83 b0 [2] a8 9c [2] 86 be [2] 92 a5 [2] 9d bf [2] 83 a2 [2] 81 a3 [2] 9a a5 [2] 86 a2 [2] 9a 8d }

  condition:
    any of them
}