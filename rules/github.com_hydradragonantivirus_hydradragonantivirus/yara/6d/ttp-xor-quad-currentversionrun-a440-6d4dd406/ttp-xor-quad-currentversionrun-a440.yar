rule TTP_XOR_QUAD_CurrentVersionRun_a440 {
  strings:
    $key_a440 = { f7 2f [2] d3 21 [2] f8 0d [2] d6 2f [2] c2 34 [2] cd 2e [2] d3 33 [2] d1 32 [2] ca 34 [2] d6 33 [2] ca 1c }

  condition:
    any of them
}