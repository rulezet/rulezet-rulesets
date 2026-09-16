rule TTP_XOR_QUAD_CurrentVersionRun_e4d1 {
  strings:
    $key_e4d1 = { b7 be [2] 93 b0 [2] b8 9c [2] 96 be [2] 82 a5 [2] 8d bf [2] 93 a2 [2] 91 a3 [2] 8a a5 [2] 96 a2 [2] 8a 8d }

  condition:
    any of them
}