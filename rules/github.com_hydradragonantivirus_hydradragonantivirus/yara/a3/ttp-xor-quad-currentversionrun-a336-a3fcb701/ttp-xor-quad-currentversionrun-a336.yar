rule TTP_XOR_QUAD_CurrentVersionRun_a336 {
  strings:
    $key_a336 = { f0 59 [2] d4 57 [2] ff 7b [2] d1 59 [2] c5 42 [2] ca 58 [2] d4 45 [2] d6 44 [2] cd 42 [2] d1 45 [2] cd 6a }

  condition:
    any of them
}