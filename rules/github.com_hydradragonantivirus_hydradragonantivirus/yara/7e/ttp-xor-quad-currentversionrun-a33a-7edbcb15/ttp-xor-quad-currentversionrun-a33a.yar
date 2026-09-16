rule TTP_XOR_QUAD_CurrentVersionRun_a33a {
  strings:
    $key_a33a = { f0 55 [2] d4 5b [2] ff 77 [2] d1 55 [2] c5 4e [2] ca 54 [2] d4 49 [2] d6 48 [2] cd 4e [2] d1 49 [2] cd 66 }

  condition:
    any of them
}