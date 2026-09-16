rule TTP_XOR_QUAD_CurrentVersionRun_ba2f {
  strings:
    $key_ba2f = { e9 40 [2] cd 4e [2] e6 62 [2] c8 40 [2] dc 5b [2] d3 41 [2] cd 5c [2] cf 5d [2] d4 5b [2] c8 5c [2] d4 73 }

  condition:
    any of them
}