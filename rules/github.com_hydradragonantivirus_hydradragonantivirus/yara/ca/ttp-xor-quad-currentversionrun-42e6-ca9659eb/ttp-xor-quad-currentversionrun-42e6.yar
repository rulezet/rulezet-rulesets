rule TTP_XOR_QUAD_CurrentVersionRun_42e6 {
  strings:
    $key_42e6 = { 11 89 [2] 35 87 [2] 1e ab [2] 30 89 [2] 24 92 [2] 2b 88 [2] 35 95 [2] 37 94 [2] 2c 92 [2] 30 95 [2] 2c ba }

  condition:
    any of them
}