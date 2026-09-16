rule TTP_XOR_QUAD_CurrentVersionRun_67e6 {
  strings:
    $key_67e6 = { 34 89 [2] 10 87 [2] 3b ab [2] 15 89 [2] 01 92 [2] 0e 88 [2] 10 95 [2] 12 94 [2] 09 92 [2] 15 95 [2] 09 ba }

  condition:
    any of them
}