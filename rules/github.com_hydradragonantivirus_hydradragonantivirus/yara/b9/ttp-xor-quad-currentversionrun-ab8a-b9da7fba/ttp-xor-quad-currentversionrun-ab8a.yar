rule TTP_XOR_QUAD_CurrentVersionRun_ab8a {
  strings:
    $key_ab8a = { f8 e5 [2] dc eb [2] f7 c7 [2] d9 e5 [2] cd fe [2] c2 e4 [2] dc f9 [2] de f8 [2] c5 fe [2] d9 f9 [2] c5 d6 }

  condition:
    any of them
}