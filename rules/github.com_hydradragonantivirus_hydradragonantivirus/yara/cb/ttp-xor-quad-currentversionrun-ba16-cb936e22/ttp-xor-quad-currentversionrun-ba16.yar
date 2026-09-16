rule TTP_XOR_QUAD_CurrentVersionRun_ba16 {
  strings:
    $key_ba16 = { e9 79 [2] cd 77 [2] e6 5b [2] c8 79 [2] dc 62 [2] d3 78 [2] cd 65 [2] cf 64 [2] d4 62 [2] c8 65 [2] d4 4a }

  condition:
    any of them
}