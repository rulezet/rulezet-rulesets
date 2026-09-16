rule TTP_XOR_QUAD_CurrentVersionRun_a3e9 {
  strings:
    $key_a3e9 = { f0 86 [2] d4 88 [2] ff a4 [2] d1 86 [2] c5 9d [2] ca 87 [2] d4 9a [2] d6 9b [2] cd 9d [2] d1 9a [2] cd b5 }

  condition:
    any of them
}