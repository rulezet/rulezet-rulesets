rule TTP_XOR_QUAD_CurrentVersionRun_ba65 {
  strings:
    $key_ba65 = { e9 0a [2] cd 04 [2] e6 28 [2] c8 0a [2] dc 11 [2] d3 0b [2] cd 16 [2] cf 17 [2] d4 11 [2] c8 16 [2] d4 39 }

  condition:
    any of them
}