rule TTP_XOR_QUAD_CurrentVersionRun_a420 {
  strings:
    $key_a420 = { f7 4f [2] d3 41 [2] f8 6d [2] d6 4f [2] c2 54 [2] cd 4e [2] d3 53 [2] d1 52 [2] ca 54 [2] d6 53 [2] ca 7c }

  condition:
    any of them
}