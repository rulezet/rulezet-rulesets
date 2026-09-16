rule TTP_XOR_QUAD_CurrentVersionRun_ba34 {
  strings:
    $key_ba34 = { e9 5b [2] cd 55 [2] e6 79 [2] c8 5b [2] dc 40 [2] d3 5a [2] cd 47 [2] cf 46 [2] d4 40 [2] c8 47 [2] d4 68 }

  condition:
    any of them
}