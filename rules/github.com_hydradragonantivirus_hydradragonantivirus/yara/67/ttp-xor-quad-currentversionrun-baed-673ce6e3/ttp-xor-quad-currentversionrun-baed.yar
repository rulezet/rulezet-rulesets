rule TTP_XOR_QUAD_CurrentVersionRun_baed {
  strings:
    $key_baed = { e9 82 [2] cd 8c [2] e6 a0 [2] c8 82 [2] dc 99 [2] d3 83 [2] cd 9e [2] cf 9f [2] d4 99 [2] c8 9e [2] d4 b1 }

  condition:
    any of them
}