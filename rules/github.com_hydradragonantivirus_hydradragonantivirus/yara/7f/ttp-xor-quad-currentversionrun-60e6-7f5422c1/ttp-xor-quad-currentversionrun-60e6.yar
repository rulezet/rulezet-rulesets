rule TTP_XOR_QUAD_CurrentVersionRun_60e6 {
  strings:
    $key_60e6 = { 33 89 [2] 17 87 [2] 3c ab [2] 12 89 [2] 06 92 [2] 09 88 [2] 17 95 [2] 15 94 [2] 0e 92 [2] 12 95 [2] 0e ba }

  condition:
    any of them
}