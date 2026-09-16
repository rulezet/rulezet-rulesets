rule TTP_XOR_QUAD_CurrentVersionRun_f5e6 {
  strings:
    $key_f5e6 = { a6 89 [2] 82 87 [2] a9 ab [2] 87 89 [2] 93 92 [2] 9c 88 [2] 82 95 [2] 80 94 [2] 9b 92 [2] 87 95 [2] 9b ba }

  condition:
    any of them
}