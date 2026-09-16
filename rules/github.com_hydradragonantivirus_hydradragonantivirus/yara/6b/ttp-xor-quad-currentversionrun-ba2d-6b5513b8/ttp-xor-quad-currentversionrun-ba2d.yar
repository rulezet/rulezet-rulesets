rule TTP_XOR_QUAD_CurrentVersionRun_ba2d {
  strings:
    $key_ba2d = { e9 42 [2] cd 4c [2] e6 60 [2] c8 42 [2] dc 59 [2] d3 43 [2] cd 5e [2] cf 5f [2] d4 59 [2] c8 5e [2] d4 71 }

  condition:
    any of them
}