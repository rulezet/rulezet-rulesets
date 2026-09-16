rule TTP_XOR_QUAD_CurrentVersionRun_7380 {
  strings:
    $key_7380 = { 20 ef [2] 04 e1 [2] 2f cd [2] 01 ef [2] 15 f4 [2] 1a ee [2] 04 f3 [2] 06 f2 [2] 1d f4 [2] 01 f3 [2] 1d dc }

  condition:
    any of them
}