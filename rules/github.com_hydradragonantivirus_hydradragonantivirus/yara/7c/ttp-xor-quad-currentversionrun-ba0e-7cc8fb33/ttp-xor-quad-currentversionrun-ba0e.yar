rule TTP_XOR_QUAD_CurrentVersionRun_ba0e {
  strings:
    $key_ba0e = { e9 61 [2] cd 6f [2] e6 43 [2] c8 61 [2] dc 7a [2] d3 60 [2] cd 7d [2] cf 7c [2] d4 7a [2] c8 7d [2] d4 52 }

  condition:
    any of them
}