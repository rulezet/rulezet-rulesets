rule TTP_XOR_QUAD_CurrentVersionRun_ba64 {
  strings:
    $key_ba64 = { e9 0b [2] cd 05 [2] e6 29 [2] c8 0b [2] dc 10 [2] d3 0a [2] cd 17 [2] cf 16 [2] d4 10 [2] c8 17 [2] d4 38 }

  condition:
    any of them
}