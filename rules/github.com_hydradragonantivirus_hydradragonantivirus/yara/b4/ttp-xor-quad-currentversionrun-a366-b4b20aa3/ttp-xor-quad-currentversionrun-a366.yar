rule TTP_XOR_QUAD_CurrentVersionRun_a366 {
  strings:
    $key_a366 = { f0 09 [2] d4 07 [2] ff 2b [2] d1 09 [2] c5 12 [2] ca 08 [2] d4 15 [2] d6 14 [2] cd 12 [2] d1 15 [2] cd 3a }

  condition:
    any of them
}