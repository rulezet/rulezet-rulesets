rule TTP_XOR_QUAD_CurrentVersionRun_a421 {
  strings:
    $key_a421 = { f7 4e [2] d3 40 [2] f8 6c [2] d6 4e [2] c2 55 [2] cd 4f [2] d3 52 [2] d1 53 [2] ca 55 [2] d6 52 [2] ca 7d }

  condition:
    any of them
}