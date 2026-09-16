rule TTP_XOR_QUAD_CurrentVersionRun_a337 {
  strings:
    $key_a337 = { f0 58 [2] d4 56 [2] ff 7a [2] d1 58 [2] c5 43 [2] ca 59 [2] d4 44 [2] d6 45 [2] cd 43 [2] d1 44 [2] cd 6b }

  condition:
    any of them
}