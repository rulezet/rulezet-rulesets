rule TTP_XOR_QUAD_CurrentVersionRun_f0e6 {
  strings:
    $key_f0e6 = { a3 89 [2] 87 87 [2] ac ab [2] 82 89 [2] 96 92 [2] 99 88 [2] 87 95 [2] 85 94 [2] 9e 92 [2] 82 95 [2] 9e ba }

  condition:
    any of them
}