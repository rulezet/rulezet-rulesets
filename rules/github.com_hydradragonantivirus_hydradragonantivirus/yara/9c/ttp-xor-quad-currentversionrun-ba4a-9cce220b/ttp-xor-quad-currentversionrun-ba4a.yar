rule TTP_XOR_QUAD_CurrentVersionRun_ba4a {
  strings:
    $key_ba4a = { e9 25 [2] cd 2b [2] e6 07 [2] c8 25 [2] dc 3e [2] d3 24 [2] cd 39 [2] cf 38 [2] d4 3e [2] c8 39 [2] d4 16 }

  condition:
    any of them
}