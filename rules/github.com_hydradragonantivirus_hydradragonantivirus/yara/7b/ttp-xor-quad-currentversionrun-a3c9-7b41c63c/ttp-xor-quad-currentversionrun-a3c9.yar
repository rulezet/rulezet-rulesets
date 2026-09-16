rule TTP_XOR_QUAD_CurrentVersionRun_a3c9 {
  strings:
    $key_a3c9 = { f0 a6 [2] d4 a8 [2] ff 84 [2] d1 a6 [2] c5 bd [2] ca a7 [2] d4 ba [2] d6 bb [2] cd bd [2] d1 ba [2] cd 95 }

  condition:
    any of them
}