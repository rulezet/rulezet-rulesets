rule TTP_XOR_QUAD_CurrentVersionRun_ba5c {
  strings:
    $key_ba5c = { e9 33 [2] cd 3d [2] e6 11 [2] c8 33 [2] dc 28 [2] d3 32 [2] cd 2f [2] cf 2e [2] d4 28 [2] c8 2f [2] d4 00 }

  condition:
    any of them
}