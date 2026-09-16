rule TTP_XOR_QUAD_CurrentVersionRun_a8d1 {
  strings:
    $key_a8d1 = { fb be [2] df b0 [2] f4 9c [2] da be [2] ce a5 [2] c1 bf [2] df a2 [2] dd a3 [2] c6 a5 [2] da a2 [2] c6 8d }

  condition:
    any of them
}