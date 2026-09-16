rule TTP_XOR_QUAD_CurrentVersionRun_a399 {
  strings:
    $key_a399 = { f0 f6 [2] d4 f8 [2] ff d4 [2] d1 f6 [2] c5 ed [2] ca f7 [2] d4 ea [2] d6 eb [2] cd ed [2] d1 ea [2] cd c5 }

  condition:
    any of them
}