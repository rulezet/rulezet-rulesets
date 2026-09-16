rule TTP_XOR_QUAD_CurrentVersionRun_42d1 {
  strings:
    $key_42d1 = { 11 be [2] 35 b0 [2] 1e 9c [2] 30 be [2] 24 a5 [2] 2b bf [2] 35 a2 [2] 37 a3 [2] 2c a5 [2] 30 a2 [2] 2c 8d }

  condition:
    any of them
}