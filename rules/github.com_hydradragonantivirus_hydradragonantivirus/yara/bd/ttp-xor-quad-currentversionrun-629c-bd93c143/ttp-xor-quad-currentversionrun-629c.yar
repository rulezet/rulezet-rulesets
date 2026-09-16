rule TTP_XOR_QUAD_CurrentVersionRun_629c {
  strings:
    $key_629c = { 31 f3 [2] 15 fd [2] 3e d1 [2] 10 f3 [2] 04 e8 [2] 0b f2 [2] 15 ef [2] 17 ee [2] 0c e8 [2] 10 ef [2] 0c c0 }

  condition:
    any of them
}