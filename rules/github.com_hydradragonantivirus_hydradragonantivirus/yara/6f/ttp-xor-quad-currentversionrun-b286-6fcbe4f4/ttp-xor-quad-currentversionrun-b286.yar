rule TTP_XOR_QUAD_CurrentVersionRun_b286 {
  strings:
    $key_b286 = { e1 e9 [2] c5 e7 [2] ee cb [2] c0 e9 [2] d4 f2 [2] db e8 [2] c5 f5 [2] c7 f4 [2] dc f2 [2] c0 f5 [2] dc da }

  condition:
    any of them
}