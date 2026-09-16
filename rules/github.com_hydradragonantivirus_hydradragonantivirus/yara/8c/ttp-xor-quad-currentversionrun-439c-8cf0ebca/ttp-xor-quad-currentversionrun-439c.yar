rule TTP_XOR_QUAD_CurrentVersionRun_439c {
  strings:
    $key_439c = { 10 f3 [2] 34 fd [2] 1f d1 [2] 31 f3 [2] 25 e8 [2] 2a f2 [2] 34 ef [2] 36 ee [2] 2d e8 [2] 31 ef [2] 2d c0 }

  condition:
    any of them
}