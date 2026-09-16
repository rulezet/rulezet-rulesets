rule TTP_XOR_QUAD_CurrentVersionRun_ba43 {
  strings:
    $key_ba43 = { e9 2c [2] cd 22 [2] e6 0e [2] c8 2c [2] dc 37 [2] d3 2d [2] cd 30 [2] cf 31 [2] d4 37 [2] c8 30 [2] d4 1f }

  condition:
    any of them
}