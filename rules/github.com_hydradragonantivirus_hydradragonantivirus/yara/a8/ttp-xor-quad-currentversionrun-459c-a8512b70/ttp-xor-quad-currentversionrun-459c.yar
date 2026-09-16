rule TTP_XOR_QUAD_CurrentVersionRun_459c {
  strings:
    $key_459c = { 16 f3 [2] 32 fd [2] 19 d1 [2] 37 f3 [2] 23 e8 [2] 2c f2 [2] 32 ef [2] 30 ee [2] 2b e8 [2] 37 ef [2] 2b c0 }

  condition:
    any of them
}