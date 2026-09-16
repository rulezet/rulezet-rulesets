rule TTP_XOR_QUAD_CurrentVersionRun_85af {
  strings:
    $key_85af = { d6 c0 [2] f2 ce [2] d9 e2 [2] f7 c0 [2] e3 db [2] ec c1 [2] f2 dc [2] f0 dd [2] eb db [2] f7 dc [2] eb f3 }

  condition:
    any of them
}