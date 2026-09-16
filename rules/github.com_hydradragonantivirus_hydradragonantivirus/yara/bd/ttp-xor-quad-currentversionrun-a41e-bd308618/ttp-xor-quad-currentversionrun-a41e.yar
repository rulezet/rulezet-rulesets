rule TTP_XOR_QUAD_CurrentVersionRun_a41e {
  strings:
    $key_a41e = { f7 71 [2] d3 7f [2] f8 53 [2] d6 71 [2] c2 6a [2] cd 70 [2] d3 6d [2] d1 6c [2] ca 6a [2] d6 6d [2] ca 42 }

  condition:
    any of them
}