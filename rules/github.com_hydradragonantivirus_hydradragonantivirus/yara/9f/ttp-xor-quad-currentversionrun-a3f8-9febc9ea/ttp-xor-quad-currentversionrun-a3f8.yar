rule TTP_XOR_QUAD_CurrentVersionRun_a3f8 {
  strings:
    $key_a3f8 = { f0 97 [2] d4 99 [2] ff b5 [2] d1 97 [2] c5 8c [2] ca 96 [2] d4 8b [2] d6 8a [2] cd 8c [2] d1 8b [2] cd a4 }

  condition:
    any of them
}