rule TTP_XOR_QUAD_CurrentVersionRun_0e9c {
  strings:
    $key_0e9c = { 5d f3 [2] 79 fd [2] 52 d1 [2] 7c f3 [2] 68 e8 [2] 67 f2 [2] 79 ef [2] 7b ee [2] 60 e8 [2] 7c ef [2] 60 c0 }

  condition:
    any of them
}