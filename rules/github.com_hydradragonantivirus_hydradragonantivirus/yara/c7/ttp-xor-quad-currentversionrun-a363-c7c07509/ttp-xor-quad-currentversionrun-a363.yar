rule TTP_XOR_QUAD_CurrentVersionRun_a363 {
  strings:
    $key_a363 = { f0 0c [2] d4 02 [2] ff 2e [2] d1 0c [2] c5 17 [2] ca 0d [2] d4 10 [2] d6 11 [2] cd 17 [2] d1 10 [2] cd 3f }

  condition:
    any of them
}