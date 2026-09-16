rule TTP_XOR_QUAD_CurrentVersionRun_ba61 {
  strings:
    $key_ba61 = { e9 0e [2] cd 00 [2] e6 2c [2] c8 0e [2] dc 15 [2] d3 0f [2] cd 12 [2] cf 13 [2] d4 15 [2] c8 12 [2] d4 3d }

  condition:
    any of them
}