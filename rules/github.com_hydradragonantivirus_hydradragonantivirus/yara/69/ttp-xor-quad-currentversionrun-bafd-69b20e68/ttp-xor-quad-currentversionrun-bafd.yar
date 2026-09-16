rule TTP_XOR_QUAD_CurrentVersionRun_bafd {
  strings:
    $key_bafd = { e9 92 [2] cd 9c [2] e6 b0 [2] c8 92 [2] dc 89 [2] d3 93 [2] cd 8e [2] cf 8f [2] d4 89 [2] c8 8e [2] d4 a1 }

  condition:
    any of them
}