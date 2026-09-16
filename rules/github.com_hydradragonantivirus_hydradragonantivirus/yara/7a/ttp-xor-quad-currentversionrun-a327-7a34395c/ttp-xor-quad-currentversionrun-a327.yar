rule TTP_XOR_QUAD_CurrentVersionRun_a327 {
  strings:
    $key_a327 = { f0 48 [2] d4 46 [2] ff 6a [2] d1 48 [2] c5 53 [2] ca 49 [2] d4 54 [2] d6 55 [2] cd 53 [2] d1 54 [2] cd 7b }

  condition:
    any of them
}