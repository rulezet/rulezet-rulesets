rule TTP_XOR_QUAD_CurrentVersionRun_a318 {
  strings:
    $key_a318 = { f0 77 [2] d4 79 [2] ff 55 [2] d1 77 [2] c5 6c [2] ca 76 [2] d4 6b [2] d6 6a [2] cd 6c [2] d1 6b [2] cd 44 }

  condition:
    any of them
}