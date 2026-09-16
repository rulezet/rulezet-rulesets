rule TTP_XOR_QUAD_CurrentVersionRun_4e9c {
  strings:
    $key_4e9c = { 1d f3 [2] 39 fd [2] 12 d1 [2] 3c f3 [2] 28 e8 [2] 27 f2 [2] 39 ef [2] 3b ee [2] 20 e8 [2] 3c ef [2] 20 c0 }

  condition:
    any of them
}