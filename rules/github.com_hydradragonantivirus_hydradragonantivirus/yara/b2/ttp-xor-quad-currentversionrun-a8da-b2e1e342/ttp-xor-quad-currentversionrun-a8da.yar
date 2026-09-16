rule TTP_XOR_QUAD_CurrentVersionRun_a8da {
  strings:
    $key_a8da = { fb b5 [2] df bb [2] f4 97 [2] da b5 [2] ce ae [2] c1 b4 [2] df a9 [2] dd a8 [2] c6 ae [2] da a9 [2] c6 86 }

  condition:
    any of them
}