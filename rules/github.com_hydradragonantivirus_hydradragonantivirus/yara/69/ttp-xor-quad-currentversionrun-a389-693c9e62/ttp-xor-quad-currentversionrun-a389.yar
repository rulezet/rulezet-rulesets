rule TTP_XOR_QUAD_CurrentVersionRun_a389 {
  strings:
    $key_a389 = { f0 e6 [2] d4 e8 [2] ff c4 [2] d1 e6 [2] c5 fd [2] ca e7 [2] d4 fa [2] d6 fb [2] cd fd [2] d1 fa [2] cd d5 }

  condition:
    any of them
}