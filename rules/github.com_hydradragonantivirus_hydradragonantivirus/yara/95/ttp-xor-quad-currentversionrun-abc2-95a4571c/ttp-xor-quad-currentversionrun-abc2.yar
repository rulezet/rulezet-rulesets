rule TTP_XOR_QUAD_CurrentVersionRun_abc2 {
  strings:
    $key_abc2 = { f8 ad [2] dc a3 [2] f7 8f [2] d9 ad [2] cd b6 [2] c2 ac [2] dc b1 [2] de b0 [2] c5 b6 [2] d9 b1 [2] c5 9e }

  condition:
    any of them
}