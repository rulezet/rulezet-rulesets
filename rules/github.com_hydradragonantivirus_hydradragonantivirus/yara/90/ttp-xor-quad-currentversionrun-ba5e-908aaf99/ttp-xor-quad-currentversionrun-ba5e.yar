rule TTP_XOR_QUAD_CurrentVersionRun_ba5e {
  strings:
    $key_ba5e = { e9 31 [2] cd 3f [2] e6 13 [2] c8 31 [2] dc 2a [2] d3 30 [2] cd 2d [2] cf 2c [2] d4 2a [2] c8 2d [2] d4 02 }

  condition:
    any of them
}