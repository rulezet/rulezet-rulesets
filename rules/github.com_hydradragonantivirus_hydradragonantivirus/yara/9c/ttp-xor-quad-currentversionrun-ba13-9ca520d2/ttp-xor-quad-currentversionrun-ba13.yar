rule TTP_XOR_QUAD_CurrentVersionRun_ba13 {
  strings:
    $key_ba13 = { e9 7c [2] cd 72 [2] e6 5e [2] c8 7c [2] dc 67 [2] d3 7d [2] cd 60 [2] cf 61 [2] d4 67 [2] c8 60 [2] d4 4f }

  condition:
    any of them
}