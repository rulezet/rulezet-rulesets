rule TTP_XOR_QUAD_CurrentVersionRun_a412 {
  strings:
    $key_a412 = { f7 7d [2] d3 73 [2] f8 5f [2] d6 7d [2] c2 66 [2] cd 7c [2] d3 61 [2] d1 60 [2] ca 66 [2] d6 61 [2] ca 4e }

  condition:
    any of them
}