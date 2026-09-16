rule TTP_XOR_QUAD_CurrentVersionRun_a3f4 {
  strings:
    $key_a3f4 = { f0 9b [2] d4 95 [2] ff b9 [2] d1 9b [2] c5 80 [2] ca 9a [2] d4 87 [2] d6 86 [2] cd 80 [2] d1 87 [2] cd a8 }

  condition:
    any of them
}