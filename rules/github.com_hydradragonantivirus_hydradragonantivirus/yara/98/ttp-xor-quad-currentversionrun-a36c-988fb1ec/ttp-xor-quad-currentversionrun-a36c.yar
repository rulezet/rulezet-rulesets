rule TTP_XOR_QUAD_CurrentVersionRun_a36c {
  strings:
    $key_a36c = { f0 03 [2] d4 0d [2] ff 21 [2] d1 03 [2] c5 18 [2] ca 02 [2] d4 1f [2] d6 1e [2] cd 18 [2] d1 1f [2] cd 30 }

  condition:
    any of them
}