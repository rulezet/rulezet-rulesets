rule TTP_XOR_QUAD_CurrentVersionRun_98b7 {
  strings:
    $key_98b7 = { cb d8 [2] ef d6 [2] c4 fa [2] ea d8 [2] fe c3 [2] f1 d9 [2] ef c4 [2] ed c5 [2] f6 c3 [2] ea c4 [2] f6 eb }

  condition:
    any of them
}