rule TTP_XOR_QUAD_CurrentVersionRun_a8cd {
  strings:
    $key_a8cd = { fb a2 [2] df ac [2] f4 80 [2] da a2 [2] ce b9 [2] c1 a3 [2] df be [2] dd bf [2] c6 b9 [2] da be [2] c6 91 }

  condition:
    any of them
}