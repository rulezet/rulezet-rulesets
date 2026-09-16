rule TTP_XOR_QUAD_CurrentVersionRun_a3e8 {
  strings:
    $key_a3e8 = { f0 87 [2] d4 89 [2] ff a5 [2] d1 87 [2] c5 9c [2] ca 86 [2] d4 9b [2] d6 9a [2] cd 9c [2] d1 9b [2] cd b4 }

  condition:
    any of them
}