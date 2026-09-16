rule TTP_XOR_QUAD_CurrentVersionRun_ba71 {
  strings:
    $key_ba71 = { e9 1e [2] cd 10 [2] e6 3c [2] c8 1e [2] dc 05 [2] d3 1f [2] cd 02 [2] cf 03 [2] d4 05 [2] c8 02 [2] d4 2d }

  condition:
    any of them
}