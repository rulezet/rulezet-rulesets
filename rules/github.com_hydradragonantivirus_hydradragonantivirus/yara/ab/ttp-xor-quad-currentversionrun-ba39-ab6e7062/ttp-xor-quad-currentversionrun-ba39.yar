rule TTP_XOR_QUAD_CurrentVersionRun_ba39 {
  strings:
    $key_ba39 = { e9 56 [2] cd 58 [2] e6 74 [2] c8 56 [2] dc 4d [2] d3 57 [2] cd 4a [2] cf 4b [2] d4 4d [2] c8 4a [2] d4 65 }

  condition:
    any of them
}