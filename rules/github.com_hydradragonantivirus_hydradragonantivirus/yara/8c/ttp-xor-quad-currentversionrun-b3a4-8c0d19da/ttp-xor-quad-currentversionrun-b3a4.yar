rule TTP_XOR_QUAD_CurrentVersionRun_b3a4 {
  strings:
    $key_b3a4 = { e0 cb [2] c4 c5 [2] ef e9 [2] c1 cb [2] d5 d0 [2] da ca [2] c4 d7 [2] c6 d6 [2] dd d0 [2] c1 d7 [2] dd f8 }

  condition:
    any of them
}