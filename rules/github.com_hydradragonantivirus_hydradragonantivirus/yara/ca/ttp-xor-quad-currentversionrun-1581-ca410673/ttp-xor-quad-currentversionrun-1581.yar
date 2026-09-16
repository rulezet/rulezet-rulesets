rule TTP_XOR_QUAD_CurrentVersionRun_1581 {
  strings:
    $key_1581 = { 46 ee [2] 62 e0 [2] 49 cc [2] 67 ee [2] 73 f5 [2] 7c ef [2] 62 f2 [2] 60 f3 [2] 7b f5 [2] 67 f2 [2] 7b dd }

  condition:
    any of them
}