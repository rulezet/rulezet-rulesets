rule TTP_XOR_QUAD_CurrentVersionRun_ba7f {
  strings:
    $key_ba7f = { e9 10 [2] cd 1e [2] e6 32 [2] c8 10 [2] dc 0b [2] d3 11 [2] cd 0c [2] cf 0d [2] d4 0b [2] c8 0c [2] d4 23 }

  condition:
    any of them
}