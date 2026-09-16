rule TTP_XOR_QUAD_CurrentVersionRun_baef {
  strings:
    $key_baef = { e9 80 [2] cd 8e [2] e6 a2 [2] c8 80 [2] dc 9b [2] d3 81 [2] cd 9c [2] cf 9d [2] d4 9b [2] c8 9c [2] d4 b3 }

  condition:
    any of them
}