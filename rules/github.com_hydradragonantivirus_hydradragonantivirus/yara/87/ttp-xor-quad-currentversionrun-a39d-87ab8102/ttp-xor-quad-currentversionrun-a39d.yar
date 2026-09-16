rule TTP_XOR_QUAD_CurrentVersionRun_a39d {
  strings:
    $key_a39d = { f0 f2 [2] d4 fc [2] ff d0 [2] d1 f2 [2] c5 e9 [2] ca f3 [2] d4 ee [2] d6 ef [2] cd e9 [2] d1 ee [2] cd c1 }

  condition:
    any of them
}