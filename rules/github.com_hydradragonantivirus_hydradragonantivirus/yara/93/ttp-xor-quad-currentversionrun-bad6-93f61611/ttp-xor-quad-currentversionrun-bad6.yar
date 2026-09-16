rule TTP_XOR_QUAD_CurrentVersionRun_bad6 {
  strings:
    $key_bad6 = { e9 b9 [2] cd b7 [2] e6 9b [2] c8 b9 [2] dc a2 [2] d3 b8 [2] cd a5 [2] cf a4 [2] d4 a2 [2] c8 a5 [2] d4 8a }

  condition:
    any of them
}