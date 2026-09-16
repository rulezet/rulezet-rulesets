rule TTP_XOR_QUAD_CurrentVersionRun_0b9c {
  strings:
    $key_0b9c = { 58 f3 [2] 7c fd [2] 57 d1 [2] 79 f3 [2] 6d e8 [2] 62 f2 [2] 7c ef [2] 7e ee [2] 65 e8 [2] 79 ef [2] 65 c0 }

  condition:
    any of them
}