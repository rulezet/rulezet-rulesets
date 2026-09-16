rule TTP_XOR_QUAD_CurrentVersionRun_ba2e {
  strings:
    $key_ba2e = { e9 41 [2] cd 4f [2] e6 63 [2] c8 41 [2] dc 5a [2] d3 40 [2] cd 5d [2] cf 5c [2] d4 5a [2] c8 5d [2] d4 72 }

  condition:
    any of them
}