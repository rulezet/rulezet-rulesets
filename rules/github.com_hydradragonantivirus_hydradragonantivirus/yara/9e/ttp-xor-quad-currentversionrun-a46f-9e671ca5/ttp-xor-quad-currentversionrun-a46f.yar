rule TTP_XOR_QUAD_CurrentVersionRun_a46f {
  strings:
    $key_a46f = { f7 00 [2] d3 0e [2] f8 22 [2] d6 00 [2] c2 1b [2] cd 01 [2] d3 1c [2] d1 1d [2] ca 1b [2] d6 1c [2] ca 33 }

  condition:
    any of them
}