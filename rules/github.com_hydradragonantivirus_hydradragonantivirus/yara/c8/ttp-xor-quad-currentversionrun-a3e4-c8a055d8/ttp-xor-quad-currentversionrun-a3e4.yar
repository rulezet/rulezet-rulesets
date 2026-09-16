rule TTP_XOR_QUAD_CurrentVersionRun_a3e4 {
  strings:
    $key_a3e4 = { f0 8b [2] d4 85 [2] ff a9 [2] d1 8b [2] c5 90 [2] ca 8a [2] d4 97 [2] d6 96 [2] cd 90 [2] d1 97 [2] cd b8 }

  condition:
    any of them
}