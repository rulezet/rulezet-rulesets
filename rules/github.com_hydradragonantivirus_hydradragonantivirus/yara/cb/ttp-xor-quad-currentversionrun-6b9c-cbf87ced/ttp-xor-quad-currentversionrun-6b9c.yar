rule TTP_XOR_QUAD_CurrentVersionRun_6b9c {
  strings:
    $key_6b9c = { 38 f3 [2] 1c fd [2] 37 d1 [2] 19 f3 [2] 0d e8 [2] 02 f2 [2] 1c ef [2] 1e ee [2] 05 e8 [2] 19 ef [2] 05 c0 }

  condition:
    any of them
}