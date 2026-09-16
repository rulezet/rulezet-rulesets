rule TTP_XOR_QUAD_CurrentVersionRun_a8b8 {
  strings:
    $key_a8b8 = { fb d7 [2] df d9 [2] f4 f5 [2] da d7 [2] ce cc [2] c1 d6 [2] df cb [2] dd ca [2] c6 cc [2] da cb [2] c6 e4 }

  condition:
    any of them
}