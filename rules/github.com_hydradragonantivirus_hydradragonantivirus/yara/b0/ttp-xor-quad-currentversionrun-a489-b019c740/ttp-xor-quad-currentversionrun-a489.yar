rule TTP_XOR_QUAD_CurrentVersionRun_a489 {
  strings:
    $key_a489 = { f7 e6 [2] d3 e8 [2] f8 c4 [2] d6 e6 [2] c2 fd [2] cd e7 [2] d3 fa [2] d1 fb [2] ca fd [2] d6 fa [2] ca d5 }

  condition:
    any of them
}