rule TTP_XOR_QUAD_CurrentVersionRun_ba75 {
  strings:
    $key_ba75 = { e9 1a [2] cd 14 [2] e6 38 [2] c8 1a [2] dc 01 [2] d3 1b [2] cd 06 [2] cf 07 [2] d4 01 [2] c8 06 [2] d4 29 }

  condition:
    any of them
}