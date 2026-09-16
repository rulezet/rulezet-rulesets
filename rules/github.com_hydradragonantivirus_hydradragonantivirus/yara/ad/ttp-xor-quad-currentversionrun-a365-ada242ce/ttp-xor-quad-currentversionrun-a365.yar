rule TTP_XOR_QUAD_CurrentVersionRun_a365 {
  strings:
    $key_a365 = { f0 0a [2] d4 04 [2] ff 28 [2] d1 0a [2] c5 11 [2] ca 0b [2] d4 16 [2] d6 17 [2] cd 11 [2] d1 16 [2] cd 39 }

  condition:
    any of them
}