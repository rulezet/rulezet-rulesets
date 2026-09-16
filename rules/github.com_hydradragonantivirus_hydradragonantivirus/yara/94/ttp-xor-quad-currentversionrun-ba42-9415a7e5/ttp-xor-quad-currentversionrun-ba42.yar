rule TTP_XOR_QUAD_CurrentVersionRun_ba42 {
  strings:
    $key_ba42 = { e9 2d [2] cd 23 [2] e6 0f [2] c8 2d [2] dc 36 [2] d3 2c [2] cd 31 [2] cf 30 [2] d4 36 [2] c8 31 [2] d4 1e }

  condition:
    any of them
}