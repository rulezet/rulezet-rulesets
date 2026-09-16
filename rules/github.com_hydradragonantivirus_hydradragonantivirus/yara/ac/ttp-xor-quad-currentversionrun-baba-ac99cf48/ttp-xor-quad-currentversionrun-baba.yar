rule TTP_XOR_QUAD_CurrentVersionRun_baba {
  strings:
    $key_baba = { e9 d5 [2] cd db [2] e6 f7 [2] c8 d5 [2] dc ce [2] d3 d4 [2] cd c9 [2] cf c8 [2] d4 ce [2] c8 c9 [2] d4 e6 }

  condition:
    any of them
}