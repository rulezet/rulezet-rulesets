rule TTP_XOR_QUAD_CurrentVersionRun_4b9c {
  strings:
    $key_4b9c = { 18 f3 [2] 3c fd [2] 17 d1 [2] 39 f3 [2] 2d e8 [2] 22 f2 [2] 3c ef [2] 3e ee [2] 25 e8 [2] 39 ef [2] 25 c0 }

  condition:
    any of them
}