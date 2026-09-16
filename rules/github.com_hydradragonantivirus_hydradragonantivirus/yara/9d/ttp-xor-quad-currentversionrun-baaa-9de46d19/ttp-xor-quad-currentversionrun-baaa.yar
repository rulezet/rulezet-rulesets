rule TTP_XOR_QUAD_CurrentVersionRun_baaa {
  strings:
    $key_baaa = { e9 c5 [2] cd cb [2] e6 e7 [2] c8 c5 [2] dc de [2] d3 c4 [2] cd d9 [2] cf d8 [2] d4 de [2] c8 d9 [2] d4 f6 }

  condition:
    any of them
}