rule TTP_XOR_QUAD_CurrentVersionRun_a367 {
  strings:
    $key_a367 = { f0 08 [2] d4 06 [2] ff 2a [2] d1 08 [2] c5 13 [2] ca 09 [2] d4 14 [2] d6 15 [2] cd 13 [2] d1 14 [2] cd 3b }

  condition:
    any of them
}