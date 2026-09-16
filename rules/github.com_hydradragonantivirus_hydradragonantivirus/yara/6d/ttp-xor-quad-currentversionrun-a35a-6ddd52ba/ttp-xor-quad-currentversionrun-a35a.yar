rule TTP_XOR_QUAD_CurrentVersionRun_a35a {
  strings:
    $key_a35a = { f0 35 [2] d4 3b [2] ff 17 [2] d1 35 [2] c5 2e [2] ca 34 [2] d4 29 [2] d6 28 [2] cd 2e [2] d1 29 [2] cd 06 }

  condition:
    any of them
}