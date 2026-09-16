rule TTP_XOR_QUAD_CurrentVersionRun_ba9a {
  strings:
    $key_ba9a = { e9 f5 [2] cd fb [2] e6 d7 [2] c8 f5 [2] dc ee [2] d3 f4 [2] cd e9 [2] cf e8 [2] d4 ee [2] c8 e9 [2] d4 c6 }

  condition:
    any of them
}