rule TTP_XOR_QUAD_CurrentVersionRun_a45e {
  strings:
    $key_a45e = { f7 31 [2] d3 3f [2] f8 13 [2] d6 31 [2] c2 2a [2] cd 30 [2] d3 2d [2] d1 2c [2] ca 2a [2] d6 2d [2] ca 02 }

  condition:
    any of them
}