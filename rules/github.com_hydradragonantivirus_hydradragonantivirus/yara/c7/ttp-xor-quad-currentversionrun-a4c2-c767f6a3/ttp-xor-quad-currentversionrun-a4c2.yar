rule TTP_XOR_QUAD_CurrentVersionRun_a4c2 {
  strings:
    $key_a4c2 = { f7 ad [2] d3 a3 [2] f8 8f [2] d6 ad [2] c2 b6 [2] cd ac [2] d3 b1 [2] d1 b0 [2] ca b6 [2] d6 b1 [2] ca 9e }

  condition:
    any of them
}