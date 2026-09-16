rule TTP_XOR_QUAD_CurrentVersionRun_ba51 {
  strings:
    $key_ba51 = { e9 3e [2] cd 30 [2] e6 1c [2] c8 3e [2] dc 25 [2] d3 3f [2] cd 22 [2] cf 23 [2] d4 25 [2] c8 22 [2] d4 0d }

  condition:
    any of them
}