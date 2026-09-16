rule TTP_XOR_QUAD_CurrentVersionRun_a8d2 {
  strings:
    $key_a8d2 = { fb bd [2] df b3 [2] f4 9f [2] da bd [2] ce a6 [2] c1 bc [2] df a1 [2] dd a0 [2] c6 a6 [2] da a1 [2] c6 8e }

  condition:
    any of them
}