rule TTP_XOR_QUAD_CurrentVersionRun_a3c7 {
  strings:
    $key_a3c7 = { f0 a8 [2] d4 a6 [2] ff 8a [2] d1 a8 [2] c5 b3 [2] ca a9 [2] d4 b4 [2] d6 b5 [2] cd b3 [2] d1 b4 [2] cd 9b }

  condition:
    any of them
}