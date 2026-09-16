rule TTP_XOR_QUAD_CurrentVersionRun_bfd3 {
  strings:
    $key_bfd3 = { ec bc [2] c8 b2 [2] e3 9e [2] cd bc [2] d9 a7 [2] d6 bd [2] c8 a0 [2] ca a1 [2] d1 a7 [2] cd a0 [2] d1 8f }

  condition:
    any of them
}