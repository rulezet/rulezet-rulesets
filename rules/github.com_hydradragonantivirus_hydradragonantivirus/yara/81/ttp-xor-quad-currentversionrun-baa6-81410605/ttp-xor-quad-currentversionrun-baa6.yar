rule TTP_XOR_QUAD_CurrentVersionRun_baa6 {
  strings:
    $key_baa6 = { e9 c9 [2] cd c7 [2] e6 eb [2] c8 c9 [2] dc d2 [2] d3 c8 [2] cd d5 [2] cf d4 [2] d4 d2 [2] c8 d5 [2] d4 fa }

  condition:
    any of them
}