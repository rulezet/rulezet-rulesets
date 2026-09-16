rule TTP_XOR_QUAD_CurrentVersionRun_d1e6 {
  strings:
    $key_d1e6 = { 82 89 [2] a6 87 [2] 8d ab [2] a3 89 [2] b7 92 [2] b8 88 [2] a6 95 [2] a4 94 [2] bf 92 [2] a3 95 [2] bf ba }

  condition:
    any of them
}