rule TTP_XOR_QUAD_CurrentVersionRun_2b81 {
  strings:
    $key_2b81 = { 78 ee [2] 5c e0 [2] 77 cc [2] 59 ee [2] 4d f5 [2] 42 ef [2] 5c f2 [2] 5e f3 [2] 45 f5 [2] 59 f2 [2] 45 dd }

  condition:
    any of them
}