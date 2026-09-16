rule TTP_XOR_QUAD_CurrentVersionRun_739c {
  strings:
    $key_739c = { 20 f3 [2] 04 fd [2] 2f d1 [2] 01 f3 [2] 15 e8 [2] 1a f2 [2] 04 ef [2] 06 ee [2] 1d e8 [2] 01 ef [2] 1d c0 }

  condition:
    any of them
}