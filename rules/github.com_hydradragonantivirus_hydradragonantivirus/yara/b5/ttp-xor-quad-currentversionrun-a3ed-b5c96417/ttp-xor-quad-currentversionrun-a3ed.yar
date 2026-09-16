rule TTP_XOR_QUAD_CurrentVersionRun_a3ed {
  strings:
    $key_a3ed = { f0 82 [2] d4 8c [2] ff a0 [2] d1 82 [2] c5 99 [2] ca 83 [2] d4 9e [2] d6 9f [2] cd 99 [2] d1 9e [2] cd b1 }

  condition:
    any of them
}