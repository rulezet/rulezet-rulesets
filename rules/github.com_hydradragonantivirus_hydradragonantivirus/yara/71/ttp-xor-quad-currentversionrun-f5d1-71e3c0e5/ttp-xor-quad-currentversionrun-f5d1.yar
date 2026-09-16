rule TTP_XOR_QUAD_CurrentVersionRun_f5d1 {
  strings:
    $key_f5d1 = { a6 be [2] 82 b0 [2] a9 9c [2] 87 be [2] 93 a5 [2] 9c bf [2] 82 a2 [2] 80 a3 [2] 9b a5 [2] 87 a2 [2] 9b 8d }

  condition:
    any of them
}