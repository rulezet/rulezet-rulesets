rule TTP_XOR_QUAD_CurrentVersionRun_ba1c {
  strings:
    $key_ba1c = { e9 73 [2] cd 7d [2] e6 51 [2] c8 73 [2] dc 68 [2] d3 72 [2] cd 6f [2] cf 6e [2] d4 68 [2] c8 6f [2] d4 40 }

  condition:
    any of them
}