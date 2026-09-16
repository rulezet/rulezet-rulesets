rule TTP_XOR_QUAD_CurrentVersionRun_a433 {
  strings:
    $key_a433 = { f7 5c [2] d3 52 [2] f8 7e [2] d6 5c [2] c2 47 [2] cd 5d [2] d3 40 [2] d1 41 [2] ca 47 [2] d6 40 [2] ca 6f }

  condition:
    any of them
}