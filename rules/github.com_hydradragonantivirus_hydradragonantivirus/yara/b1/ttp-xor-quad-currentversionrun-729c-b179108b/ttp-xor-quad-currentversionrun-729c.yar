rule TTP_XOR_QUAD_CurrentVersionRun_729c {
  strings:
    $key_729c = { 21 f3 [2] 05 fd [2] 2e d1 [2] 00 f3 [2] 14 e8 [2] 1b f2 [2] 05 ef [2] 07 ee [2] 1c e8 [2] 00 ef [2] 1c c0 }

  condition:
    any of them
}