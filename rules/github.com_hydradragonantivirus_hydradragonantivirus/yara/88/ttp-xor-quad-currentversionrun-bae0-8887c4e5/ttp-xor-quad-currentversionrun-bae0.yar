rule TTP_XOR_QUAD_CurrentVersionRun_bae0 {
  strings:
    $key_bae0 = { e9 8f [2] cd 81 [2] e6 ad [2] c8 8f [2] dc 94 [2] d3 8e [2] cd 93 [2] cf 92 [2] d4 94 [2] c8 93 [2] d4 bc }

  condition:
    any of them
}