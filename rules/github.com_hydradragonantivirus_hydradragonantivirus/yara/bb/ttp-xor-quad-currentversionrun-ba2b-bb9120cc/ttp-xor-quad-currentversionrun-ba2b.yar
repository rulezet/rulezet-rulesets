rule TTP_XOR_QUAD_CurrentVersionRun_ba2b {
  strings:
    $key_ba2b = { e9 44 [2] cd 4a [2] e6 66 [2] c8 44 [2] dc 5f [2] d3 45 [2] cd 58 [2] cf 59 [2] d4 5f [2] c8 58 [2] d4 77 }

  condition:
    any of them
}