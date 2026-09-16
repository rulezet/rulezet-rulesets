rule TTP_XOR_QUAD_CurrentVersionRun_a3c6 {
  strings:
    $key_a3c6 = { f0 a9 [2] d4 a7 [2] ff 8b [2] d1 a9 [2] c5 b2 [2] ca a8 [2] d4 b5 [2] d6 b4 [2] cd b2 [2] d1 b5 [2] cd 9a }

  condition:
    any of them
}