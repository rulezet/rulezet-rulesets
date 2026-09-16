rule TTP_XOR_QUAD_CurrentVersionRun_bac7 {
  strings:
    $key_bac7 = { e9 a8 [2] cd a6 [2] e6 8a [2] c8 a8 [2] dc b3 [2] d3 a9 [2] cd b4 [2] cf b5 [2] d4 b3 [2] c8 b4 [2] d4 9b }

  condition:
    any of them
}