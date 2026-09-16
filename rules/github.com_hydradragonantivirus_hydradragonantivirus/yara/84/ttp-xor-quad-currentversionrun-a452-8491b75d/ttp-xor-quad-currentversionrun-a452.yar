rule TTP_XOR_QUAD_CurrentVersionRun_a452 {
  strings:
    $key_a452 = { f7 3d [2] d3 33 [2] f8 1f [2] d6 3d [2] c2 26 [2] cd 3c [2] d3 21 [2] d1 20 [2] ca 26 [2] d6 21 [2] ca 0e }

  condition:
    any of them
}