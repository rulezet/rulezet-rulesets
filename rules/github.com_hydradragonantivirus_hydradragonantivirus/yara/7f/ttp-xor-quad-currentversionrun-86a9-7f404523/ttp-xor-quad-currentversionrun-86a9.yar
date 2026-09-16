rule TTP_XOR_QUAD_CurrentVersionRun_86a9 {
  strings:
    $key_86a9 = { d5 c6 [2] f1 c8 [2] da e4 [2] f4 c6 [2] e0 dd [2] ef c7 [2] f1 da [2] f3 db [2] e8 dd [2] f4 da [2] e8 f5 }

  condition:
    any of them
}