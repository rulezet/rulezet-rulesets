rule TTP_XOR_QUAD_CurrentVersionRun_a898 {
  strings:
    $key_a898 = { fb f7 [2] df f9 [2] f4 d5 [2] da f7 [2] ce ec [2] c1 f6 [2] df eb [2] dd ea [2] c6 ec [2] da eb [2] c6 c4 }

  condition:
    any of them
}