rule TTP_XOR_QUAD_CurrentVersionRun_a338 {
  strings:
    $key_a338 = { f0 57 [2] d4 59 [2] ff 75 [2] d1 57 [2] c5 4c [2] ca 56 [2] d4 4b [2] d6 4a [2] cd 4c [2] d1 4b [2] cd 64 }

  condition:
    any of them
}