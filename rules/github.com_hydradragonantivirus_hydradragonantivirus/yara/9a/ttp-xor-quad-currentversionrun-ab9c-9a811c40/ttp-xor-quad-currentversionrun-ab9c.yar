rule TTP_XOR_QUAD_CurrentVersionRun_ab9c {
  strings:
    $key_ab9c = { f8 f3 [2] dc fd [2] f7 d1 [2] d9 f3 [2] cd e8 [2] c2 f2 [2] dc ef [2] de ee [2] c5 e8 [2] d9 ef [2] c5 c0 }

  condition:
    any of them
}