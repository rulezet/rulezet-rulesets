rule TTP_XOR_QUAD_CurrentVersionRun_0281 {
  strings:
    $key_0281 = { 51 ee [2] 75 e0 [2] 5e cc [2] 70 ee [2] 64 f5 [2] 6b ef [2] 75 f2 [2] 77 f3 [2] 6c f5 [2] 70 f2 [2] 6c dd }

  condition:
    any of them
}