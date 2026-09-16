rule TTP_XOR_QUAD_CurrentVersionRun_749c {
  strings:
    $key_749c = { 27 f3 [2] 03 fd [2] 28 d1 [2] 06 f3 [2] 12 e8 [2] 1d f2 [2] 03 ef [2] 01 ee [2] 1a e8 [2] 06 ef [2] 1a c0 }

  condition:
    any of them
}