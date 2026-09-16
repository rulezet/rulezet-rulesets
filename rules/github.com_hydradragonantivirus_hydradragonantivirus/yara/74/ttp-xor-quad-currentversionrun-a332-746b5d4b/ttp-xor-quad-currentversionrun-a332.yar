rule TTP_XOR_QUAD_CurrentVersionRun_a332 {
  strings:
    $key_a332 = { f0 5d [2] d4 53 [2] ff 7f [2] d1 5d [2] c5 46 [2] ca 5c [2] d4 41 [2] d6 40 [2] cd 46 [2] d1 41 [2] cd 6e }

  condition:
    any of them
}