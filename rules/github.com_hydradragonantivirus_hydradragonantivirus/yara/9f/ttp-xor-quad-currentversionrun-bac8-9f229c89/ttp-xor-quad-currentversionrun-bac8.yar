rule TTP_XOR_QUAD_CurrentVersionRun_bac8 {
  strings:
    $key_bac8 = { e9 a7 [2] cd a9 [2] e6 85 [2] c8 a7 [2] dc bc [2] d3 a6 [2] cd bb [2] cf ba [2] d4 bc [2] c8 bb [2] d4 94 }

  condition:
    any of them
}