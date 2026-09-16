rule TTP_XOR_QUAD_CurrentVersionRun_bac2 {
  strings:
    $key_bac2 = { e9 ad [2] cd a3 [2] e6 8f [2] c8 ad [2] dc b6 [2] d3 ac [2] cd b1 [2] cf b0 [2] d4 b6 [2] c8 b1 [2] d4 9e }

  condition:
    any of them
}