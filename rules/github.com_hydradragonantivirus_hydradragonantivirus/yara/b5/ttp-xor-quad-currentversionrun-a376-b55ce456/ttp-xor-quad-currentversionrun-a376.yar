rule TTP_XOR_QUAD_CurrentVersionRun_a376 {
  strings:
    $key_a376 = { f0 19 [2] d4 17 [2] ff 3b [2] d1 19 [2] c5 02 [2] ca 18 [2] d4 05 [2] d6 04 [2] cd 02 [2] d1 05 [2] cd 2a }

  condition:
    any of them
}