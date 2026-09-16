rule TTP_XOR_QUAD_CurrentVersionRun_ba05 {
  strings:
    $key_ba05 = { e9 6a [2] cd 64 [2] e6 48 [2] c8 6a [2] dc 71 [2] d3 6b [2] cd 76 [2] cf 77 [2] d4 71 [2] c8 76 [2] d4 59 }

  condition:
    any of them
}