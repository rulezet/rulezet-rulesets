rule TTP_XOR_QUAD_CurrentVersionRun_a326 {
  strings:
    $key_a326 = { f0 49 [2] d4 47 [2] ff 6b [2] d1 49 [2] c5 52 [2] ca 48 [2] d4 55 [2] d6 54 [2] cd 52 [2] d1 55 [2] cd 7a }

  condition:
    any of them
}