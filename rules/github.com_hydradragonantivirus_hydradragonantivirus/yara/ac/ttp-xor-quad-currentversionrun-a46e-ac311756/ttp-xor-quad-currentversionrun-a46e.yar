rule TTP_XOR_QUAD_CurrentVersionRun_a46e {
  strings:
    $key_a46e = { f7 01 [2] d3 0f [2] f8 23 [2] d6 01 [2] c2 1a [2] cd 00 [2] d3 1d [2] d1 1c [2] ca 1a [2] d6 1d [2] ca 32 }

  condition:
    any of them
}