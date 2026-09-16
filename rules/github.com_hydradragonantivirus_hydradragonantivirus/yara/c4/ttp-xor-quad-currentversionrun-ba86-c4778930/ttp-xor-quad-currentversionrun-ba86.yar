rule TTP_XOR_QUAD_CurrentVersionRun_ba86 {
  strings:
    $key_ba86 = { e9 e9 [2] cd e7 [2] e6 cb [2] c8 e9 [2] dc f2 [2] d3 e8 [2] cd f5 [2] cf f4 [2] d4 f2 [2] c8 f5 [2] d4 da }

  condition:
    any of them
}