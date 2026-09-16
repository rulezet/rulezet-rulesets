rule TTP_XOR_QUAD_CurrentVersionRun_bfa6 {
  strings:
    $key_bfa6 = { ec c9 [2] c8 c7 [2] e3 eb [2] cd c9 [2] d9 d2 [2] d6 c8 [2] c8 d5 [2] ca d4 [2] d1 d2 [2] cd d5 [2] d1 fa }

  condition:
    any of them
}