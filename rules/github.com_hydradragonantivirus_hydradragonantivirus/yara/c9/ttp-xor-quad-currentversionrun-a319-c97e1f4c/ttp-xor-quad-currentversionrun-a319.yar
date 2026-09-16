rule TTP_XOR_QUAD_CurrentVersionRun_a319 {
  strings:
    $key_a319 = { f0 76 [2] d4 78 [2] ff 54 [2] d1 76 [2] c5 6d [2] ca 77 [2] d4 6a [2] d6 6b [2] cd 6d [2] d1 6a [2] cd 45 }

  condition:
    any of them
}