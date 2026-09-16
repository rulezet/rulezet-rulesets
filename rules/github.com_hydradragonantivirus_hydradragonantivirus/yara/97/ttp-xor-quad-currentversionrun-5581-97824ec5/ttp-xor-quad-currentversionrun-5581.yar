rule TTP_XOR_QUAD_CurrentVersionRun_5581 {
  strings:
    $key_5581 = { 06 ee [2] 22 e0 [2] 09 cc [2] 27 ee [2] 33 f5 [2] 3c ef [2] 22 f2 [2] 20 f3 [2] 3b f5 [2] 27 f2 [2] 3b dd }

  condition:
    any of them
}