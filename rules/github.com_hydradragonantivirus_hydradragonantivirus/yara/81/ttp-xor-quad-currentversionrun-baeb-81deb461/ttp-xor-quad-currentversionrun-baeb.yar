rule TTP_XOR_QUAD_CurrentVersionRun_baeb {
  strings:
    $key_baeb = { e9 84 [2] cd 8a [2] e6 a6 [2] c8 84 [2] dc 9f [2] d3 85 [2] cd 98 [2] cf 99 [2] d4 9f [2] c8 98 [2] d4 b7 }

  condition:
    any of them
}