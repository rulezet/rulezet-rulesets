rule TTP_XOR_QUAD_CurrentVersionRun_a357 {
  strings:
    $key_a357 = { f0 38 [2] d4 36 [2] ff 1a [2] d1 38 [2] c5 23 [2] ca 39 [2] d4 24 [2] d6 25 [2] cd 23 [2] d1 24 [2] cd 0b }

  condition:
    any of them
}