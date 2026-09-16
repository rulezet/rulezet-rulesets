rule TTP_XOR_QUAD_CurrentVersionRun_a4d6 {
  strings:
    $key_a4d6 = { f7 b9 [2] d3 b7 [2] f8 9b [2] d6 b9 [2] c2 a2 [2] cd b8 [2] d3 a5 [2] d1 a4 [2] ca a2 [2] d6 a5 [2] ca 8a }

  condition:
    any of them
}