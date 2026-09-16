rule TTP_XOR_QUAD_CurrentVersionRun_ba6f {
  strings:
    $key_ba6f = { e9 00 [2] cd 0e [2] e6 22 [2] c8 00 [2] dc 1b [2] d3 01 [2] cd 1c [2] cf 1d [2] d4 1b [2] c8 1c [2] d4 33 }

  condition:
    any of them
}