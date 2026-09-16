rule TTP_XOR_QUAD_CurrentVersionRun_5f9c {
  strings:
    $key_5f9c = { 0c f3 [2] 28 fd [2] 03 d1 [2] 2d f3 [2] 39 e8 [2] 36 f2 [2] 28 ef [2] 2a ee [2] 31 e8 [2] 2d ef [2] 31 c0 }

  condition:
    any of them
}