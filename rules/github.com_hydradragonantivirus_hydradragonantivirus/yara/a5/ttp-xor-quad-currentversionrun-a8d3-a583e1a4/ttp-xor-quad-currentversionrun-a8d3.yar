rule TTP_XOR_QUAD_CurrentVersionRun_a8d3 {
  strings:
    $key_a8d3 = { fb bc [2] df b2 [2] f4 9e [2] da bc [2] ce a7 [2] c1 bd [2] df a0 [2] dd a1 [2] c6 a7 [2] da a0 [2] c6 8f }

  condition:
    any of them
}