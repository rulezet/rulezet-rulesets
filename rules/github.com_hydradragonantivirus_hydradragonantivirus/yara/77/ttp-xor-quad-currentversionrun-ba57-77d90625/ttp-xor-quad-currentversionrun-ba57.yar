rule TTP_XOR_QUAD_CurrentVersionRun_ba57 {
  strings:
    $key_ba57 = { e9 38 [2] cd 36 [2] e6 1a [2] c8 38 [2] dc 23 [2] d3 39 [2] cd 24 [2] cf 25 [2] d4 23 [2] c8 24 [2] d4 0b }

  condition:
    any of them
}