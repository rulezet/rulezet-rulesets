rule TTP_XOR_QUAD_CurrentVersionRun_bafb {
  strings:
    $key_bafb = { e9 94 [2] cd 9a [2] e6 b6 [2] c8 94 [2] dc 8f [2] d3 95 [2] cd 88 [2] cf 89 [2] d4 8f [2] c8 88 [2] d4 a7 }

  condition:
    any of them
}