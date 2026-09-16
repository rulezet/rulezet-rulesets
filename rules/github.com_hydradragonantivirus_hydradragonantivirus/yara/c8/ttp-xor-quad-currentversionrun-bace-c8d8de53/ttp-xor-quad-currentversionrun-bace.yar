rule TTP_XOR_QUAD_CurrentVersionRun_bace {
  strings:
    $key_bace = { e9 a1 [2] cd af [2] e6 83 [2] c8 a1 [2] dc ba [2] d3 a0 [2] cd bd [2] cf bc [2] d4 ba [2] c8 bd [2] d4 92 }

  condition:
    any of them
}