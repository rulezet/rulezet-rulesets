rule TTP_XOR_QUAD_CurrentVersionRun_1f9c {
  strings:
    $key_1f9c = { 4c f3 [2] 68 fd [2] 43 d1 [2] 6d f3 [2] 79 e8 [2] 76 f2 [2] 68 ef [2] 6a ee [2] 71 e8 [2] 6d ef [2] 71 c0 }

  condition:
    any of them
}