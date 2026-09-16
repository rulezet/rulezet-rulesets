rule TTP_XOR_QUAD_CurrentVersionRun_ab80 {
  strings:
    $key_ab80 = { f8 ef [2] dc e1 [2] f7 cd [2] d9 ef [2] cd f4 [2] c2 ee [2] dc f3 [2] de f2 [2] c5 f4 [2] d9 f3 [2] c5 dc }

  condition:
    any of them
}