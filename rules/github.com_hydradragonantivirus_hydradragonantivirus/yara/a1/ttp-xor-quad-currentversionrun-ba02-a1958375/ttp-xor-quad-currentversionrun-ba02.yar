rule TTP_XOR_QUAD_CurrentVersionRun_ba02 {
  strings:
    $key_ba02 = { e9 6d [2] cd 63 [2] e6 4f [2] c8 6d [2] dc 76 [2] d3 6c [2] cd 71 [2] cf 70 [2] d4 76 [2] c8 71 [2] d4 5e }

  condition:
    any of them
}