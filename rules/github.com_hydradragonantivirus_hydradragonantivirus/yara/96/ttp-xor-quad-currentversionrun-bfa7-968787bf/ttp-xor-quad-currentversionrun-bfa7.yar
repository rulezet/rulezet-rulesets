rule TTP_XOR_QUAD_CurrentVersionRun_bfa7 {
  strings:
    $key_bfa7 = { ec c8 [2] c8 c6 [2] e3 ea [2] cd c8 [2] d9 d3 [2] d6 c9 [2] c8 d4 [2] ca d5 [2] d1 d3 [2] cd d4 [2] d1 fb }

  condition:
    any of them
}