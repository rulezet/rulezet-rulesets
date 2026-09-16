rule TTP_XOR_QUAD_CurrentVersionRun_a354 {
  strings:
    $key_a354 = { f0 3b [2] d4 35 [2] ff 19 [2] d1 3b [2] c5 20 [2] ca 3a [2] d4 27 [2] d6 26 [2] cd 20 [2] d1 27 [2] cd 08 }

  condition:
    any of them
}