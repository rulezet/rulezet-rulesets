rule TTP_XOR_QUAD_CurrentVersionRun_a41f {
  strings:
    $key_a41f = { f7 70 [2] d3 7e [2] f8 52 [2] d6 70 [2] c2 6b [2] cd 71 [2] d3 6c [2] d1 6d [2] ca 6b [2] d6 6c [2] ca 43 }

  condition:
    any of them
}