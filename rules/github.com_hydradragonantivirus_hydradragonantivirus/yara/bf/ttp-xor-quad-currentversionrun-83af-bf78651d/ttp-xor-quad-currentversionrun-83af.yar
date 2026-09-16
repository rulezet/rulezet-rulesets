rule TTP_XOR_QUAD_CurrentVersionRun_83af {
  strings:
    $key_83af = { d0 c0 [2] f4 ce [2] df e2 [2] f1 c0 [2] e5 db [2] ea c1 [2] f4 dc [2] f6 dd [2] ed db [2] f1 dc [2] ed f3 }

  condition:
    any of them
}