rule TTP_XOR_QUAD_CurrentVersionRun_a44e {
  strings:
    $key_a44e = { f7 21 [2] d3 2f [2] f8 03 [2] d6 21 [2] c2 3a [2] cd 20 [2] d3 3d [2] d1 3c [2] ca 3a [2] d6 3d [2] ca 12 }

  condition:
    any of them
}