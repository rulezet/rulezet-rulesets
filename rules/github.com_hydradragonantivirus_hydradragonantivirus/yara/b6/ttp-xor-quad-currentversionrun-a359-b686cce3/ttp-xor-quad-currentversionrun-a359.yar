rule TTP_XOR_QUAD_CurrentVersionRun_a359 {
  strings:
    $key_a359 = { f0 36 [2] d4 38 [2] ff 14 [2] d1 36 [2] c5 2d [2] ca 37 [2] d4 2a [2] d6 2b [2] cd 2d [2] d1 2a [2] cd 05 }

  condition:
    any of them
}