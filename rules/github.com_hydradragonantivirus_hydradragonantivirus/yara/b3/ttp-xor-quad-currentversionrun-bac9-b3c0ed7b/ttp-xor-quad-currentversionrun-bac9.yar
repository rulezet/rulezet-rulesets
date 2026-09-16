rule TTP_XOR_QUAD_CurrentVersionRun_bac9 {
  strings:
    $key_bac9 = { e9 a6 [2] cd a8 [2] e6 84 [2] c8 a6 [2] dc bd [2] d3 a7 [2] cd ba [2] cf bb [2] d4 bd [2] c8 ba [2] d4 95 }

  condition:
    any of them
}