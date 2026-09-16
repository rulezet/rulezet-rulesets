rule TTP_XOR_QUAD_CurrentVersionRun_ba24 {
  strings:
    $key_ba24 = { e9 4b [2] cd 45 [2] e6 69 [2] c8 4b [2] dc 50 [2] d3 4a [2] cd 57 [2] cf 56 [2] d4 50 [2] c8 57 [2] d4 78 }

  condition:
    any of them
}