rule TTP_XOR_QUAD_CurrentVersionRun_2581 {
  strings:
    $key_2581 = { 76 ee [2] 52 e0 [2] 79 cc [2] 57 ee [2] 43 f5 [2] 4c ef [2] 52 f2 [2] 50 f3 [2] 4b f5 [2] 57 f2 [2] 4b dd }

  condition:
    any of them
}