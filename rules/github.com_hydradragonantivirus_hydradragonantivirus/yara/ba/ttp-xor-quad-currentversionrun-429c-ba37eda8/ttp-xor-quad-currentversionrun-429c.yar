rule TTP_XOR_QUAD_CurrentVersionRun_429c {
  strings:
    $key_429c = { 11 f3 [2] 35 fd [2] 1e d1 [2] 30 f3 [2] 24 e8 [2] 2b f2 [2] 35 ef [2] 37 ee [2] 2c e8 [2] 30 ef [2] 2c c0 }

  condition:
    any of them
}