rule TTP_XOR_QUAD_CurrentVersionRun_ba48 {
  strings:
    $key_ba48 = { e9 27 [2] cd 29 [2] e6 05 [2] c8 27 [2] dc 3c [2] d3 26 [2] cd 3b [2] cf 3a [2] d4 3c [2] c8 3b [2] d4 14 }

  condition:
    any of them
}