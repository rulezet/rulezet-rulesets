rule TTP_XOR_QUAD_CurrentVersionRun_a374 {
  strings:
    $key_a374 = { f0 1b [2] d4 15 [2] ff 39 [2] d1 1b [2] c5 00 [2] ca 1a [2] d4 07 [2] d6 06 [2] cd 00 [2] d1 07 [2] cd 28 }

  condition:
    any of them
}