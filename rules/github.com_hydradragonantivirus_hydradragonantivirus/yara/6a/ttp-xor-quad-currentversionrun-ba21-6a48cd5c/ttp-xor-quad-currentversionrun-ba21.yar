rule TTP_XOR_QUAD_CurrentVersionRun_ba21 {
  strings:
    $key_ba21 = { e9 4e [2] cd 40 [2] e6 6c [2] c8 4e [2] dc 55 [2] d3 4f [2] cd 52 [2] cf 53 [2] d4 55 [2] c8 52 [2] d4 7d }

  condition:
    any of them
}