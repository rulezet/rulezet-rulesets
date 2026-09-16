rule TTP_XOR_QUAD_CurrentVersionRun_ba6e {
  strings:
    $key_ba6e = { e9 01 [2] cd 0f [2] e6 23 [2] c8 01 [2] dc 1a [2] d3 00 [2] cd 1d [2] cf 1c [2] d4 1a [2] c8 1d [2] d4 32 }

  condition:
    any of them
}