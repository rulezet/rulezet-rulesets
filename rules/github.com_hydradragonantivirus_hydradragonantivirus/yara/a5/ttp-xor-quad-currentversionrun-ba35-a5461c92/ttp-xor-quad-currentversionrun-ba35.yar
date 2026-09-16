rule TTP_XOR_QUAD_CurrentVersionRun_ba35 {
  strings:
    $key_ba35 = { e9 5a [2] cd 54 [2] e6 78 [2] c8 5a [2] dc 41 [2] d3 5b [2] cd 46 [2] cf 47 [2] d4 41 [2] c8 46 [2] d4 69 }

  condition:
    any of them
}