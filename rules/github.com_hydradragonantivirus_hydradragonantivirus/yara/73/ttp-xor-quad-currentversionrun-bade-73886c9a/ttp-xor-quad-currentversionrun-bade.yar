rule TTP_XOR_QUAD_CurrentVersionRun_bade {
  strings:
    $key_bade = { e9 b1 [2] cd bf [2] e6 93 [2] c8 b1 [2] dc aa [2] d3 b0 [2] cd ad [2] cf ac [2] d4 aa [2] c8 ad [2] d4 82 }

  condition:
    any of them
}