rule TTP_XOR_QUAD_CurrentVersionRun_ba4c {
  strings:
    $key_ba4c = { e9 23 [2] cd 2d [2] e6 01 [2] c8 23 [2] dc 38 [2] d3 22 [2] cd 3f [2] cf 3e [2] d4 38 [2] c8 3f [2] d4 10 }

  condition:
    any of them
}