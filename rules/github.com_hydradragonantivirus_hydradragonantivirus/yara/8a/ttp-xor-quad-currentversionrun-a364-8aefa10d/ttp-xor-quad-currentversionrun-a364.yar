rule TTP_XOR_QUAD_CurrentVersionRun_a364 {
  strings:
    $key_a364 = { f0 0b [2] d4 05 [2] ff 29 [2] d1 0b [2] c5 10 [2] ca 0a [2] d4 17 [2] d6 16 [2] cd 10 [2] d1 17 [2] cd 38 }

  condition:
    any of them
}