rule TTP_XOR_QUAD_CurrentVersionRun_ba46 {
  strings:
    $key_ba46 = { e9 29 [2] cd 27 [2] e6 0b [2] c8 29 [2] dc 32 [2] d3 28 [2] cd 35 [2] cf 34 [2] d4 32 [2] c8 35 [2] d4 1a }

  condition:
    any of them
}