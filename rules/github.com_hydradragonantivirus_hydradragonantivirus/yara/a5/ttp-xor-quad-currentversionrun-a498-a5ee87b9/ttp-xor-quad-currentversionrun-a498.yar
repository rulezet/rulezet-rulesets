rule TTP_XOR_QUAD_CurrentVersionRun_a498 {
  strings:
    $key_a498 = { f7 f7 [2] d3 f9 [2] f8 d5 [2] d6 f7 [2] c2 ec [2] cd f6 [2] d3 eb [2] d1 ea [2] ca ec [2] d6 eb [2] ca c4 }

  condition:
    any of them
}