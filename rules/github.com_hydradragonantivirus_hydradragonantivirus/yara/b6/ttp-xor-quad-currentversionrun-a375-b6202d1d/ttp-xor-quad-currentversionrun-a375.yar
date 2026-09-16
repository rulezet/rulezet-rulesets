rule TTP_XOR_QUAD_CurrentVersionRun_a375 {
  strings:
    $key_a375 = { f0 1a [2] d4 14 [2] ff 38 [2] d1 1a [2] c5 01 [2] ca 1b [2] d4 06 [2] d6 07 [2] cd 01 [2] d1 06 [2] cd 29 }

  condition:
    any of them
}