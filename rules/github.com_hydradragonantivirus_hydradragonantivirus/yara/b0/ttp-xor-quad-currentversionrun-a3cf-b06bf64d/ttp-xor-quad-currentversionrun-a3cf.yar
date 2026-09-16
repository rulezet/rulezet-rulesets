rule TTP_XOR_QUAD_CurrentVersionRun_a3cf {
  strings:
    $key_a3cf = { f0 a0 [2] d4 ae [2] ff 82 [2] d1 a0 [2] c5 bb [2] ca a1 [2] d4 bc [2] d6 bd [2] cd bb [2] d1 bc [2] cd 93 }

  condition:
    any of them
}