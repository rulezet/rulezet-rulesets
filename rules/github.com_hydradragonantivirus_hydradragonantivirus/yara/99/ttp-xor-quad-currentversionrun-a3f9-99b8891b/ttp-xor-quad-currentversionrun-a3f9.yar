rule TTP_XOR_QUAD_CurrentVersionRun_a3f9 {
  strings:
    $key_a3f9 = { f0 96 [2] d4 98 [2] ff b4 [2] d1 96 [2] c5 8d [2] ca 97 [2] d4 8a [2] d6 8b [2] cd 8d [2] d1 8a [2] cd a5 }

  condition:
    any of them
}