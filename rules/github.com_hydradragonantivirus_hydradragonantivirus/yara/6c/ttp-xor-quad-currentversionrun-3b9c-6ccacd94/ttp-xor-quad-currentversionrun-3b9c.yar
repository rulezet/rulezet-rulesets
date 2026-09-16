rule TTP_XOR_QUAD_CurrentVersionRun_3b9c {
  strings:
    $key_3b9c = { 68 f3 [2] 4c fd [2] 67 d1 [2] 49 f3 [2] 5d e8 [2] 52 f2 [2] 4c ef [2] 4e ee [2] 55 e8 [2] 49 ef [2] 55 c0 }

  condition:
    any of them
}