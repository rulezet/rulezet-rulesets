rule TTP_XOR_QUAD_CurrentVersionRun_a431 {
  strings:
    $key_a431 = { f7 5e [2] d3 50 [2] f8 7c [2] d6 5e [2] c2 45 [2] cd 5f [2] d3 42 [2] d1 43 [2] ca 45 [2] d6 42 [2] ca 6d }

  condition:
    any of them
}