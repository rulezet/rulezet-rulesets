rule TTP_XOR_QUAD_CurrentVersionRun_a432 {
  strings:
    $key_a432 = { f7 5d [2] d3 53 [2] f8 7f [2] d6 5d [2] c2 46 [2] cd 5c [2] d3 41 [2] d1 40 [2] ca 46 [2] d6 41 [2] ca 6e }

  condition:
    any of them
}