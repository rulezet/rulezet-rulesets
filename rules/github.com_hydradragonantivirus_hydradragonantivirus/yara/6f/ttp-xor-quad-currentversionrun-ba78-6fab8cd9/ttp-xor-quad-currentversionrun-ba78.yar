rule TTP_XOR_QUAD_CurrentVersionRun_ba78 {
  strings:
    $key_ba78 = { e9 17 [2] cd 19 [2] e6 35 [2] c8 17 [2] dc 0c [2] d3 16 [2] cd 0b [2] cf 0a [2] d4 0c [2] c8 0b [2] d4 24 }

  condition:
    any of them
}