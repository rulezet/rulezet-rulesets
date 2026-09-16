rule TTP_XOR_QUAD_CurrentVersionRun_a424 {
  strings:
    $key_a424 = { f7 4b [2] d3 45 [2] f8 69 [2] d6 4b [2] c2 50 [2] cd 4a [2] d3 57 [2] d1 56 [2] ca 50 [2] d6 57 [2] ca 78 }

  condition:
    any of them
}