rule TTP_XOR_QUAD_CurrentVersionRun_ba0d {
  strings:
    $key_ba0d = { e9 62 [2] cd 6c [2] e6 40 [2] c8 62 [2] dc 79 [2] d3 63 [2] cd 7e [2] cf 7f [2] d4 79 [2] c8 7e [2] d4 51 }

  condition:
    any of them
}