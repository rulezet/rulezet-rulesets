rule TTP_XOR_QUAD_CurrentVersionRun_a4fd {
  strings:
    $key_a4fd = { f7 92 [2] d3 9c [2] f8 b0 [2] d6 92 [2] c2 89 [2] cd 93 [2] d3 8e [2] d1 8f [2] ca 89 [2] d6 8e [2] ca a1 }

  condition:
    any of them
}