rule TTP_XOR_QUAD_CurrentVersionRun_a44f {
  strings:
    $key_a44f = { f7 20 [2] d3 2e [2] f8 02 [2] d6 20 [2] c2 3b [2] cd 21 [2] d3 3c [2] d1 3d [2] ca 3b [2] d6 3c [2] ca 13 }

  condition:
    any of them
}