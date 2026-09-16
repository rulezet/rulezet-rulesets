rule TTP_XOR_QUAD_CurrentVersionRun_a36a {
  strings:
    $key_a36a = { f0 05 [2] d4 0b [2] ff 27 [2] d1 05 [2] c5 1e [2] ca 04 [2] d4 19 [2] d6 18 [2] cd 1e [2] d1 19 [2] cd 36 }

  condition:
    any of them
}