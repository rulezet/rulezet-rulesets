rule TTP_XOR_QUAD_CurrentVersionRun_a462 {
  strings:
    $key_a462 = { f7 0d [2] d3 03 [2] f8 2f [2] d6 0d [2] c2 16 [2] cd 0c [2] d3 11 [2] d1 10 [2] ca 16 [2] d6 11 [2] ca 3e }

  condition:
    any of them
}