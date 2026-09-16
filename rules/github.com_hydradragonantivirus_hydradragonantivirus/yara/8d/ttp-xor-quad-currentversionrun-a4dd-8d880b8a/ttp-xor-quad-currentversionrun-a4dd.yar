rule TTP_XOR_QUAD_CurrentVersionRun_a4dd {
  strings:
    $key_a4dd = { f7 b2 [2] d3 bc [2] f8 90 [2] d6 b2 [2] c2 a9 [2] cd b3 [2] d3 ae [2] d1 af [2] ca a9 [2] d6 ae [2] ca 81 }

  condition:
    any of them
}