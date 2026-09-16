rule TTP_XOR_QUAD_CurrentVersionRun_a4e8 {
  strings:
    $key_a4e8 = { f7 87 [2] d3 89 [2] f8 a5 [2] d6 87 [2] c2 9c [2] cd 86 [2] d3 9b [2] d1 9a [2] ca 9c [2] d6 9b [2] ca b4 }

  condition:
    any of them
}