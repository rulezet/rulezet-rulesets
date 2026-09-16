rule TTP_XOR_QUAD_CurrentVersionRun_ba41 {
  strings:
    $key_ba41 = { e9 2e [2] cd 20 [2] e6 0c [2] c8 2e [2] dc 35 [2] d3 2f [2] cd 32 [2] cf 33 [2] d4 35 [2] c8 32 [2] d4 1d }

  condition:
    any of them
}