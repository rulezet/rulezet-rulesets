rule TTP_XOR_QUAD_CurrentVersionRun_a47d {
  strings:
    $key_a47d = { f7 12 [2] d3 1c [2] f8 30 [2] d6 12 [2] c2 09 [2] cd 13 [2] d3 0e [2] d1 0f [2] ca 09 [2] d6 0e [2] ca 21 }

  condition:
    any of them
}