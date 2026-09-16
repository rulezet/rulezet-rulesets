rule TTP_XOR_QUAD_CurrentVersionRun_ba36 {
  strings:
    $key_ba36 = { e9 59 [2] cd 57 [2] e6 7b [2] c8 59 [2] dc 42 [2] d3 58 [2] cd 45 [2] cf 44 [2] d4 42 [2] c8 45 [2] d4 6a }

  condition:
    any of them
}