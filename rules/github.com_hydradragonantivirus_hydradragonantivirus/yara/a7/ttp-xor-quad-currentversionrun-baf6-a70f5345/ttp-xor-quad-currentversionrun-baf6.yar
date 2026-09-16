rule TTP_XOR_QUAD_CurrentVersionRun_baf6 {
  strings:
    $key_baf6 = { e9 99 [2] cd 97 [2] e6 bb [2] c8 99 [2] dc 82 [2] d3 98 [2] cd 85 [2] cf 84 [2] d4 82 [2] c8 85 [2] d4 aa }

  condition:
    any of them
}