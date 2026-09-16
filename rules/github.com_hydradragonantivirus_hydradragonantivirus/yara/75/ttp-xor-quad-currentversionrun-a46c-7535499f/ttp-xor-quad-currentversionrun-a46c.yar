rule TTP_XOR_QUAD_CurrentVersionRun_a46c {
  strings:
    $key_a46c = { f7 03 [2] d3 0d [2] f8 21 [2] d6 03 [2] c2 18 [2] cd 02 [2] d3 1f [2] d1 1e [2] ca 18 [2] d6 1f [2] ca 30 }

  condition:
    any of them
}