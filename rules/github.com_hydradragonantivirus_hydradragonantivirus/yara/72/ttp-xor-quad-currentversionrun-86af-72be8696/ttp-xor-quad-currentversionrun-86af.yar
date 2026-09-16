rule TTP_XOR_QUAD_CurrentVersionRun_86af {
  strings:
    $key_86af = { d5 c0 [2] f1 ce [2] da e2 [2] f4 c0 [2] e0 db [2] ef c1 [2] f1 dc [2] f3 dd [2] e8 db [2] f4 dc [2] e8 f3 }

  condition:
    any of them
}