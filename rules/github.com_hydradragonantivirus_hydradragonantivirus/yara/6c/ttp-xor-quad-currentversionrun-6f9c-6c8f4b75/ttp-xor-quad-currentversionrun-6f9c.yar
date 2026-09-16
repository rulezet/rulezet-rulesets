rule TTP_XOR_QUAD_CurrentVersionRun_6f9c {
  strings:
    $key_6f9c = { 3c f3 [2] 18 fd [2] 33 d1 [2] 1d f3 [2] 09 e8 [2] 06 f2 [2] 18 ef [2] 1a ee [2] 01 e8 [2] 1d ef [2] 01 c0 }

  condition:
    any of them
}