rule TTP_XOR_QUAD_CurrentVersionRun_ba7e {
  strings:
    $key_ba7e = { e9 11 [2] cd 1f [2] e6 33 [2] c8 11 [2] dc 0a [2] d3 10 [2] cd 0d [2] cf 0c [2] d4 0a [2] c8 0d [2] d4 22 }

  condition:
    any of them
}