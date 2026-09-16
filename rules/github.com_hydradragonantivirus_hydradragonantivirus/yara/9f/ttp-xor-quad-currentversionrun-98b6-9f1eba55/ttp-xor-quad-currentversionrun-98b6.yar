rule TTP_XOR_QUAD_CurrentVersionRun_98b6 {
  strings:
    $key_98b6 = { cb d9 [2] ef d7 [2] c4 fb [2] ea d9 [2] fe c2 [2] f1 d8 [2] ef c5 [2] ed c4 [2] f6 c2 [2] ea c5 [2] f6 ea }

  condition:
    any of them
}