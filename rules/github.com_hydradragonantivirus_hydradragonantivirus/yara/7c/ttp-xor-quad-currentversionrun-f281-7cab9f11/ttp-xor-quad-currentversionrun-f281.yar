rule TTP_XOR_QUAD_CurrentVersionRun_f281 {
  strings:
    $key_f281 = { a1 ee [2] 85 e0 [2] ae cc [2] 80 ee [2] 94 f5 [2] 9b ef [2] 85 f2 [2] 87 f3 [2] 9c f5 [2] 80 f2 [2] 9c dd }

  condition:
    any of them
}