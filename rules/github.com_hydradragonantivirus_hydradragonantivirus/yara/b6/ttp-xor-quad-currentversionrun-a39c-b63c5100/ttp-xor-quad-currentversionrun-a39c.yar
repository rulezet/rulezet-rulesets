rule TTP_XOR_QUAD_CurrentVersionRun_a39c {
  strings:
    $key_a39c = { f0 f3 [2] d4 fd [2] ff d1 [2] d1 f3 [2] c5 e8 [2] ca f2 [2] d4 ef [2] d6 ee [2] cd e8 [2] d1 ef [2] cd c0 }

  condition:
    any of them
}