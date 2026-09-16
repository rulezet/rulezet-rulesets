rule TTP_XOR_QUAD_CurrentVersionRun_afb7 {
  strings:
    $key_afb7 = { fc d8 [2] d8 d6 [2] f3 fa [2] dd d8 [2] c9 c3 [2] c6 d9 [2] d8 c4 [2] da c5 [2] c1 c3 [2] dd c4 [2] c1 eb }

  condition:
    any of them
}