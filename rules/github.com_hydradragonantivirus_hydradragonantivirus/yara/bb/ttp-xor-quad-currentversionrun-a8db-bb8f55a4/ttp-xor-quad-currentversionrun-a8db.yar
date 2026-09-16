rule TTP_XOR_QUAD_CurrentVersionRun_a8db {
  strings:
    $key_a8db = { fb b4 [2] df ba [2] f4 96 [2] da b4 [2] ce af [2] c1 b5 [2] df a8 [2] dd a9 [2] c6 af [2] da a8 [2] c6 87 }

  condition:
    any of them
}