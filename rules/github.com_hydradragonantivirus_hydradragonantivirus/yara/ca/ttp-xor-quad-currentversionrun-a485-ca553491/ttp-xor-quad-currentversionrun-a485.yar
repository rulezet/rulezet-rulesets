rule TTP_XOR_QUAD_CurrentVersionRun_a485 {
  strings:
    $key_a485 = { f7 ea [2] d3 e4 [2] f8 c8 [2] d6 ea [2] c2 f1 [2] cd eb [2] d3 f6 [2] d1 f7 [2] ca f1 [2] d6 f6 [2] ca d9 }

  condition:
    any of them
}