rule TTP_XOR_QUAD_CurrentVersionRun_a42b {
  strings:
    $key_a42b = { f7 44 [2] d3 4a [2] f8 66 [2] d6 44 [2] c2 5f [2] cd 45 [2] d3 58 [2] d1 59 [2] ca 5f [2] d6 58 [2] ca 77 }

  condition:
    any of them
}