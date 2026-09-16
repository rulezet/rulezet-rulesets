rule TTP_XOR_QUAD_CurrentVersionRun_a3ef {
  strings:
    $key_a3ef = { f0 80 [2] d4 8e [2] ff a2 [2] d1 80 [2] c5 9b [2] ca 81 [2] d4 9c [2] d6 9d [2] cd 9b [2] d1 9c [2] cd b3 }

  condition:
    any of them
}