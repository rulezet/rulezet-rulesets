rule TTP_XOR_QUAD_CurrentVersionRun_50e6 {
  strings:
    $key_50e6 = { 03 89 [2] 27 87 [2] 0c ab [2] 22 89 [2] 36 92 [2] 39 88 [2] 27 95 [2] 25 94 [2] 3e 92 [2] 22 95 [2] 3e ba }

  condition:
    any of them
}