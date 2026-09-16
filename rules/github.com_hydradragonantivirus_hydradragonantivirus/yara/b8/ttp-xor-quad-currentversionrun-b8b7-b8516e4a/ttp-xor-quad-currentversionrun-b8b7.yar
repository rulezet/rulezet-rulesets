rule TTP_XOR_QUAD_CurrentVersionRun_b8b7 {
  strings:
    $key_b8b7 = { eb d8 [2] cf d6 [2] e4 fa [2] ca d8 [2] de c3 [2] d1 d9 [2] cf c4 [2] cd c5 [2] d6 c3 [2] ca c4 [2] d6 eb }

  condition:
    any of them
}