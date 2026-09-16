rule TTP_XOR_QUAD_CurrentVersionRun_a323 {
  strings:
    $key_a323 = { f0 4c [2] d4 42 [2] ff 6e [2] d1 4c [2] c5 57 [2] ca 4d [2] d4 50 [2] d6 51 [2] cd 57 [2] d1 50 [2] cd 7f }

  condition:
    any of them
}