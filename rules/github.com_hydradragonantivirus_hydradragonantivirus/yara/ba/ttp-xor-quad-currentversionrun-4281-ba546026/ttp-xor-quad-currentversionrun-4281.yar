rule TTP_XOR_QUAD_CurrentVersionRun_4281 {
  strings:
    $key_4281 = { 11 ee [2] 35 e0 [2] 1e cc [2] 30 ee [2] 24 f5 [2] 2b ef [2] 35 f2 [2] 37 f3 [2] 2c f5 [2] 30 f2 [2] 2c dd }

  condition:
    any of them
}