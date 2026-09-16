rule TTP_XOR_QUAD_CurrentVersionRun_7b9c {
  strings:
    $key_7b9c = { 28 f3 [2] 0c fd [2] 27 d1 [2] 09 f3 [2] 1d e8 [2] 12 f2 [2] 0c ef [2] 0e ee [2] 15 e8 [2] 09 ef [2] 15 c0 }

  condition:
    any of them
}