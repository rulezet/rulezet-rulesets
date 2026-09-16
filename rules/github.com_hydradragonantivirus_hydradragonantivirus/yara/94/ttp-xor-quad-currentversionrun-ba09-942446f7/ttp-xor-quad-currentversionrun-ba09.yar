rule TTP_XOR_QUAD_CurrentVersionRun_ba09 {
  strings:
    $key_ba09 = { e9 66 [2] cd 68 [2] e6 44 [2] c8 66 [2] dc 7d [2] d3 67 [2] cd 7a [2] cf 7b [2] d4 7d [2] c8 7a [2] d4 55 }

  condition:
    any of them
}