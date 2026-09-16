rule TTP_XOR_QUAD_CurrentVersionRun_209c {
  strings:
    $key_209c = { 73 f3 [2] 57 fd [2] 7c d1 [2] 52 f3 [2] 46 e8 [2] 49 f2 [2] 57 ef [2] 55 ee [2] 4e e8 [2] 52 ef [2] 4e c0 }

  condition:
    any of them
}