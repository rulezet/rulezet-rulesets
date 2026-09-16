rule TTP_XOR_QUAD_CurrentVersionRun_85a4 {
  strings:
    $key_85a4 = { d6 cb [2] f2 c5 [2] d9 e9 [2] f7 cb [2] e3 d0 [2] ec ca [2] f2 d7 [2] f0 d6 [2] eb d0 [2] f7 d7 [2] eb f8 }

  condition:
    any of them
}