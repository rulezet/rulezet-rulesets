rule TTP_XOR_QUAD_CurrentVersionRun_a488 {
  strings:
    $key_a488 = { f7 e7 [2] d3 e9 [2] f8 c5 [2] d6 e7 [2] c2 fc [2] cd e6 [2] d3 fb [2] d1 fa [2] ca fc [2] d6 fb [2] ca d4 }

  condition:
    any of them
}