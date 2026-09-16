rule TTP_XOR_QUAD_CurrentVersionRun_a8a5 {
  strings:
    $key_a8a5 = { fb ca [2] df c4 [2] f4 e8 [2] da ca [2] ce d1 [2] c1 cb [2] df d6 [2] dd d7 [2] c6 d1 [2] da d6 [2] c6 f9 }

  condition:
    any of them
}