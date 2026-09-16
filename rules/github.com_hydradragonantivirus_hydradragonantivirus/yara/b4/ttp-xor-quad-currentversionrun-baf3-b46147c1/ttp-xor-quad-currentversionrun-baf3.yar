rule TTP_XOR_QUAD_CurrentVersionRun_baf3 {
  strings:
    $key_baf3 = { e9 9c [2] cd 92 [2] e6 be [2] c8 9c [2] dc 87 [2] d3 9d [2] cd 80 [2] cf 81 [2] d4 87 [2] c8 80 [2] d4 af }

  condition:
    any of them
}