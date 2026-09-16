rule TTP_XOR_QUAD_CurrentVersionRun_e581 {
  strings:
    $key_e581 = { b6 ee [2] 92 e0 [2] b9 cc [2] 97 ee [2] 83 f5 [2] 8c ef [2] 92 f2 [2] 90 f3 [2] 8b f5 [2] 97 f2 [2] 8b dd }

  condition:
    any of them
}