rule TTP_XOR_QUAD_CurrentVersionRun_ba40 {
  strings:
    $key_ba40 = { e9 2f [2] cd 21 [2] e6 0d [2] c8 2f [2] dc 34 [2] d3 2e [2] cd 33 [2] cf 32 [2] d4 34 [2] c8 33 [2] d4 1c }

  condition:
    any of them
}