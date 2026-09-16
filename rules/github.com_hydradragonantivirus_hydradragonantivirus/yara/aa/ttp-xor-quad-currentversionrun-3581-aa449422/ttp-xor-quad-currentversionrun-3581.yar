rule TTP_XOR_QUAD_CurrentVersionRun_3581 {
  strings:
    $key_3581 = { 66 ee [2] 42 e0 [2] 69 cc [2] 47 ee [2] 53 f5 [2] 5c ef [2] 42 f2 [2] 40 f3 [2] 5b f5 [2] 47 f2 [2] 5b dd }

  condition:
    any of them
}