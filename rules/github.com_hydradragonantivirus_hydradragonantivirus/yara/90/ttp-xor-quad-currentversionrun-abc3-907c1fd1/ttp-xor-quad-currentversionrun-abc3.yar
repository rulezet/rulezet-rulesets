rule TTP_XOR_QUAD_CurrentVersionRun_abc3 {
  strings:
    $key_abc3 = { f8 ac [2] dc a2 [2] f7 8e [2] d9 ac [2] cd b7 [2] c2 ad [2] dc b0 [2] de b1 [2] c5 b7 [2] d9 b0 [2] c5 9f }

  condition:
    any of them
}