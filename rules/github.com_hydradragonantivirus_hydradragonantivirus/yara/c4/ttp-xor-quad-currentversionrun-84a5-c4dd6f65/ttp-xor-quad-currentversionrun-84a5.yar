rule TTP_XOR_QUAD_CurrentVersionRun_84a5 {
  strings:
    $key_84a5 = { d7 ca [2] f3 c4 [2] d8 e8 [2] f6 ca [2] e2 d1 [2] ed cb [2] f3 d6 [2] f1 d7 [2] ea d1 [2] f6 d6 [2] ea f9 }

  condition:
    any of them
}