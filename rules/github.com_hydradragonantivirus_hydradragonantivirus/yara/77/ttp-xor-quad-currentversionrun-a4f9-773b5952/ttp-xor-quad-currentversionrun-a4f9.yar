rule TTP_XOR_QUAD_CurrentVersionRun_a4f9 {
  strings:
    $key_a4f9 = { f7 96 [2] d3 98 [2] f8 b4 [2] d6 96 [2] c2 8d [2] cd 97 [2] d3 8a [2] d1 8b [2] ca 8d [2] d6 8a [2] ca a5 }

  condition:
    any of them
}