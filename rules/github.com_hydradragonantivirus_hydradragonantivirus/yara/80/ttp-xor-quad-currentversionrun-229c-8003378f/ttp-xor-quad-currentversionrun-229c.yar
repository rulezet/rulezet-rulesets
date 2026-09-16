rule TTP_XOR_QUAD_CurrentVersionRun_229c {
  strings:
    $key_229c = { 71 f3 [2] 55 fd [2] 7e d1 [2] 50 f3 [2] 44 e8 [2] 4b f2 [2] 55 ef [2] 57 ee [2] 4c e8 [2] 50 ef [2] 4c c0 }

  condition:
    any of them
}