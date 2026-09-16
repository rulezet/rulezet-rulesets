rule TTP_XOR_QUAD_CurrentVersionRun_ba6c {
  strings:
    $key_ba6c = { e9 03 [2] cd 0d [2] e6 21 [2] c8 03 [2] dc 18 [2] d3 02 [2] cd 1f [2] cf 1e [2] d4 18 [2] c8 1f [2] d4 30 }

  condition:
    any of them
}