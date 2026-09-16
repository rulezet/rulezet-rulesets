rule TTP_XOR_QUAD_CurrentVersionRun_a8ce {
  strings:
    $key_a8ce = { fb a1 [2] df af [2] f4 83 [2] da a1 [2] ce ba [2] c1 a0 [2] df bd [2] dd bc [2] c6 ba [2] da bd [2] c6 92 }

  condition:
    any of them
}