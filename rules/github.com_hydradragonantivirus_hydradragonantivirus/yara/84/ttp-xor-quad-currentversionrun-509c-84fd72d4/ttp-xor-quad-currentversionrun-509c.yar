rule TTP_XOR_QUAD_CurrentVersionRun_509c {
  strings:
    $key_509c = { 03 f3 [2] 27 fd [2] 0c d1 [2] 22 f3 [2] 36 e8 [2] 39 f2 [2] 27 ef [2] 25 ee [2] 3e e8 [2] 22 ef [2] 3e c0 }

  condition:
    any of them
}