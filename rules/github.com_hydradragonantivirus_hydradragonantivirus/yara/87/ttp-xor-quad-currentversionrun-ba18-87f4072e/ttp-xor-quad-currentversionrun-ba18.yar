rule TTP_XOR_QUAD_CurrentVersionRun_ba18 {
  strings:
    $key_ba18 = { e9 77 [2] cd 79 [2] e6 55 [2] c8 77 [2] dc 6c [2] d3 76 [2] cd 6b [2] cf 6a [2] d4 6c [2] c8 6b [2] d4 44 }

  condition:
    any of them
}