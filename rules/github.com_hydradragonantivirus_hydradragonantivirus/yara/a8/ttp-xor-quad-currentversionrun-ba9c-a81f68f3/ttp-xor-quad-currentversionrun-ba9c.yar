rule TTP_XOR_QUAD_CurrentVersionRun_ba9c {
  strings:
    $key_ba9c = { e9 f3 [2] cd fd [2] e6 d1 [2] c8 f3 [2] dc e8 [2] d3 f2 [2] cd ef [2] cf ee [2] d4 e8 [2] c8 ef [2] d4 c0 }

  condition:
    any of them
}