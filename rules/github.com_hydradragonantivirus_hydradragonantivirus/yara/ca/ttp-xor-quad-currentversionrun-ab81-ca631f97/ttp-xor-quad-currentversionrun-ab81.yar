rule TTP_XOR_QUAD_CurrentVersionRun_ab81 {
  strings:
    $key_ab81 = { f8 ee [2] dc e0 [2] f7 cc [2] d9 ee [2] cd f5 [2] c2 ef [2] dc f2 [2] de f3 [2] c5 f5 [2] d9 f2 [2] c5 dd }

  condition:
    any of them
}