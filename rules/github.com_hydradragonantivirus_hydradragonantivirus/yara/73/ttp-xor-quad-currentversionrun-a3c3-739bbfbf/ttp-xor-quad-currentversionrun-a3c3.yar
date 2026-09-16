rule TTP_XOR_QUAD_CurrentVersionRun_a3c3 {
  strings:
    $key_a3c3 = { f0 ac [2] d4 a2 [2] ff 8e [2] d1 ac [2] c5 b7 [2] ca ad [2] d4 b0 [2] d6 b1 [2] cd b7 [2] d1 b0 [2] cd 9f }

  condition:
    any of them
}