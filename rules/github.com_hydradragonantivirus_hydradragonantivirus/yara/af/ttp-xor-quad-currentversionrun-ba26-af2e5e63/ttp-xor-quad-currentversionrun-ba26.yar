rule TTP_XOR_QUAD_CurrentVersionRun_ba26 {
  strings:
    $key_ba26 = { e9 49 [2] cd 47 [2] e6 6b [2] c8 49 [2] dc 52 [2] d3 48 [2] cd 55 [2] cf 54 [2] d4 52 [2] c8 55 [2] d4 7a }

  condition:
    any of them
}