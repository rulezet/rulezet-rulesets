rule TTP_XOR_QUAD_CurrentVersionRun_baf9 {
  strings:
    $key_baf9 = { e9 96 [2] cd 98 [2] e6 b4 [2] c8 96 [2] dc 8d [2] d3 97 [2] cd 8a [2] cf 8b [2] d4 8d [2] c8 8a [2] d4 a5 }

  condition:
    any of them
}