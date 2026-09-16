rule TTP_XOR_QUAD_CurrentVersionRun_42f7 {
  strings:
    $key_42f7 = { 11 98 [2] 35 96 [2] 1e ba [2] 30 98 [2] 24 83 [2] 2b 99 [2] 35 84 [2] 37 85 [2] 2c 83 [2] 30 84 [2] 2c ab }

  condition:
    any of them
}