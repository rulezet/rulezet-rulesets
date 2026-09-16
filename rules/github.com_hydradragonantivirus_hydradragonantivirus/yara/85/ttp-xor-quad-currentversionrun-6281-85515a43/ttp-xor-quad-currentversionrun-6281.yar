rule TTP_XOR_QUAD_CurrentVersionRun_6281 {
  strings:
    $key_6281 = { 31 ee [2] 15 e0 [2] 3e cc [2] 10 ee [2] 04 f5 [2] 0b ef [2] 15 f2 [2] 17 f3 [2] 0c f5 [2] 10 f2 [2] 0c dd }

  condition:
    any of them
}