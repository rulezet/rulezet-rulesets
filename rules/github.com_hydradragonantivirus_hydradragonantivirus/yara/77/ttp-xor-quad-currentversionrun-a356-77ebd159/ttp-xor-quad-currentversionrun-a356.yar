rule TTP_XOR_QUAD_CurrentVersionRun_a356 {
  strings:
    $key_a356 = { f0 39 [2] d4 37 [2] ff 1b [2] d1 39 [2] c5 22 [2] ca 38 [2] d4 25 [2] d6 24 [2] cd 22 [2] d1 25 [2] cd 0a }

  condition:
    any of them
}