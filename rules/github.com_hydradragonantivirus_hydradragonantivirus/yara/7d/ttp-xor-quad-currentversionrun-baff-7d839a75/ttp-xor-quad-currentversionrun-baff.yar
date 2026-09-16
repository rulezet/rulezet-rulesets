rule TTP_XOR_QUAD_CurrentVersionRun_baff {
  strings:
    $key_baff = { e9 90 [2] cd 9e [2] e6 b2 [2] c8 90 [2] dc 8b [2] d3 91 [2] cd 8c [2] cf 8d [2] d4 8b [2] c8 8c [2] d4 a3 }

  condition:
    any of them
}