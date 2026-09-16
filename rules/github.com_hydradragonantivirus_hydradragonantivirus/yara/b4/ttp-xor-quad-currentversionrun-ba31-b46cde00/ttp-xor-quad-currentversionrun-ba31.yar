rule TTP_XOR_QUAD_CurrentVersionRun_ba31 {
  strings:
    $key_ba31 = { e9 5e [2] cd 50 [2] e6 7c [2] c8 5e [2] dc 45 [2] d3 5f [2] cd 42 [2] cf 43 [2] d4 45 [2] c8 42 [2] d4 6d }

  condition:
    any of them
}