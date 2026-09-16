rule TTP_XOR_QUAD_CurrentVersionRun_d6d1 {
  strings:
    $key_d6d1 = { 85 be [2] a1 b0 [2] 8a 9c [2] a4 be [2] b0 a5 [2] bf bf [2] a1 a2 [2] a3 a3 [2] b8 a5 [2] a4 a2 [2] b8 8d }

  condition:
    any of them
}