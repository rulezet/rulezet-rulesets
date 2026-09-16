rule TTP_XOR_QUAD_CurrentVersionRun_ba60 {
  strings:
    $key_ba60 = { e9 0f [2] cd 01 [2] e6 2d [2] c8 0f [2] dc 14 [2] d3 0e [2] cd 13 [2] cf 12 [2] d4 14 [2] c8 13 [2] d4 3c }

  condition:
    any of them
}