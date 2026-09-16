rule TTP_XOR_QUAD_CurrentVersionRun_7e9c {
  strings:
    $key_7e9c = { 2d f3 [2] 09 fd [2] 22 d1 [2] 0c f3 [2] 18 e8 [2] 17 f2 [2] 09 ef [2] 0b ee [2] 10 e8 [2] 0c ef [2] 10 c0 }

  condition:
    any of them
}