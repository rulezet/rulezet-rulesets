rule TTP_XOR_QUAD_CurrentVersionRun_a322 {
  strings:
    $key_a322 = { f0 4d [2] d4 43 [2] ff 6f [2] d1 4d [2] c5 56 [2] ca 4c [2] d4 51 [2] d6 50 [2] cd 56 [2] d1 51 [2] cd 7e }

  condition:
    any of them
}