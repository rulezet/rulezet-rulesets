rule TTP_XOR_QUAD_CurrentVersionRun_a307 {
  strings:
    $key_a307 = { f0 68 [2] d4 66 [2] ff 4a [2] d1 68 [2] c5 73 [2] ca 69 [2] d4 74 [2] d6 75 [2] cd 73 [2] d1 74 [2] cd 5b }

  condition:
    any of them
}