rule TTP_XOR_QUAD_CurrentVersionRun_ba10 {
  strings:
    $key_ba10 = { e9 7f [2] cd 71 [2] e6 5d [2] c8 7f [2] dc 64 [2] d3 7e [2] cd 63 [2] cf 62 [2] d4 64 [2] c8 63 [2] d4 4c }

  condition:
    any of them
}