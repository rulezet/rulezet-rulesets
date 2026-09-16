rule TTP_XOR_QUAD_CurrentVersionRun_ba5d {
  strings:
    $key_ba5d = { e9 32 [2] cd 3c [2] e6 10 [2] c8 32 [2] dc 29 [2] d3 33 [2] cd 2e [2] cf 2f [2] d4 29 [2] c8 2e [2] d4 01 }

  condition:
    any of them
}