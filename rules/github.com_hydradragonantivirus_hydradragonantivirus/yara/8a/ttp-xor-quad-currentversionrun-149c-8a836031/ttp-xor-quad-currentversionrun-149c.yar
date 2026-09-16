rule TTP_XOR_QUAD_CurrentVersionRun_149c {
  strings:
    $key_149c = { 47 f3 [2] 63 fd [2] 48 d1 [2] 66 f3 [2] 72 e8 [2] 7d f2 [2] 63 ef [2] 61 ee [2] 7a e8 [2] 66 ef [2] 7a c0 }

  condition:
    any of them
}