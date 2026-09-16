rule TTP_XOR_QUAD_CurrentVersionRun_bab3 {
  strings:
    $key_bab3 = { e9 dc [2] cd d2 [2] e6 fe [2] c8 dc [2] dc c7 [2] d3 dd [2] cd c0 [2] cf c1 [2] d4 c7 [2] c8 c0 [2] d4 ef }

  condition:
    any of them
}