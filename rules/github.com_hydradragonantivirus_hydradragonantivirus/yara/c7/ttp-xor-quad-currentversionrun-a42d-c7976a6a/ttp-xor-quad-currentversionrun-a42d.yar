rule TTP_XOR_QUAD_CurrentVersionRun_a42d {
  strings:
    $key_a42d = { f7 42 [2] d3 4c [2] f8 60 [2] d6 42 [2] c2 59 [2] cd 43 [2] d3 5e [2] d1 5f [2] ca 59 [2] d6 5e [2] ca 71 }

  condition:
    any of them
}