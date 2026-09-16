rule TTP_XOR_QUAD_CurrentVersionRun_a4f1 {
  strings:
    $key_a4f1 = { f7 9e [2] d3 90 [2] f8 bc [2] d6 9e [2] c2 85 [2] cd 9f [2] d3 82 [2] d1 83 [2] ca 85 [2] d6 82 [2] ca ad }

  condition:
    any of them
}