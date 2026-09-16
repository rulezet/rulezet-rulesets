rule TTP_XOR_QUAD_CurrentVersionRun_ba22 {
  strings:
    $key_ba22 = { e9 4d [2] cd 43 [2] e6 6f [2] c8 4d [2] dc 56 [2] d3 4c [2] cd 51 [2] cf 50 [2] d4 56 [2] c8 51 [2] d4 7e }

  condition:
    any of them
}