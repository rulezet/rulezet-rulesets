rule TTP_XOR_QUAD_CurrentVersionRun_a378 {
  strings:
    $key_a378 = { f0 17 [2] d4 19 [2] ff 35 [2] d1 17 [2] c5 0c [2] ca 16 [2] d4 0b [2] d6 0a [2] cd 0c [2] d1 0b [2] cd 24 }

  condition:
    any of them
}