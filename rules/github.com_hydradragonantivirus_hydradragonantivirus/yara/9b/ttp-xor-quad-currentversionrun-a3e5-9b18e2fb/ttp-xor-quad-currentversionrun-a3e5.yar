rule TTP_XOR_QUAD_CurrentVersionRun_a3e5 {
  strings:
    $key_a3e5 = { f0 8a [2] d4 84 [2] ff a8 [2] d1 8a [2] c5 91 [2] ca 8b [2] d4 96 [2] d6 97 [2] cd 91 [2] d1 96 [2] cd b9 }

  condition:
    any of them
}