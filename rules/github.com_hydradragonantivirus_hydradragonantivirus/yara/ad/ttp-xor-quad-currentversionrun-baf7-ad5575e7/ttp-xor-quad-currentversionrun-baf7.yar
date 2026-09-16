rule TTP_XOR_QUAD_CurrentVersionRun_baf7 {
  strings:
    $key_baf7 = { e9 98 [2] cd 96 [2] e6 ba [2] c8 98 [2] dc 83 [2] d3 99 [2] cd 84 [2] cf 85 [2] d4 83 [2] c8 84 [2] d4 ab }

  condition:
    any of them
}