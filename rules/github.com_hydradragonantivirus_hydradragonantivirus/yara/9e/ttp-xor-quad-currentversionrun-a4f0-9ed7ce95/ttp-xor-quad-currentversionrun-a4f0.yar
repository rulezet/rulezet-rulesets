rule TTP_XOR_QUAD_CurrentVersionRun_a4f0 {
  strings:
    $key_a4f0 = { f7 9f [2] d3 91 [2] f8 bd [2] d6 9f [2] c2 84 [2] cd 9e [2] d3 83 [2] d1 82 [2] ca 84 [2] d6 83 [2] ca ac }

  condition:
    any of them
}