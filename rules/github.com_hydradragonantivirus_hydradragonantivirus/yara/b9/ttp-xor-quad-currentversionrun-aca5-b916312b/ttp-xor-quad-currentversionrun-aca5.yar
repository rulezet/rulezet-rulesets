rule TTP_XOR_QUAD_CurrentVersionRun_aca5 {
  strings:
    $key_aca5 = { ff ca [2] db c4 [2] f0 e8 [2] de ca [2] ca d1 [2] c5 cb [2] db d6 [2] d9 d7 [2] c2 d1 [2] de d6 [2] c2 f9 }

  condition:
    any of them
}