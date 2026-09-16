rule TTP_XOR_QUAD_CurrentVersionRun_a8a4 {
  strings:
    $key_a8a4 = { fb cb [2] df c5 [2] f4 e9 [2] da cb [2] ce d0 [2] c1 ca [2] df d7 [2] dd d6 [2] c6 d0 [2] da d7 [2] c6 f8 }

  condition:
    any of them
}