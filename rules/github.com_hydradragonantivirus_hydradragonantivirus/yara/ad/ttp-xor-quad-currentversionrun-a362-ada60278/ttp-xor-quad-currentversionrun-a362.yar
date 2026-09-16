rule TTP_XOR_QUAD_CurrentVersionRun_a362 {
  strings:
    $key_a362 = { f0 0d [2] d4 03 [2] ff 2f [2] d1 0d [2] c5 16 [2] ca 0c [2] d4 11 [2] d6 10 [2] cd 16 [2] d1 11 [2] cd 3e }

  condition:
    any of them
}