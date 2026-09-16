rule TTP_XOR_QUAD_CurrentVersionRun_ba28 {
  strings:
    $key_ba28 = { e9 47 [2] cd 49 [2] e6 65 [2] c8 47 [2] dc 5c [2] d3 46 [2] cd 5b [2] cf 5a [2] d4 5c [2] c8 5b [2] d4 74 }

  condition:
    any of them
}