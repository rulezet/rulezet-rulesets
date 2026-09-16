rule TTP_XOR_QUAD_CurrentVersionRun_96af {
  strings:
    $key_96af = { c5 c0 [2] e1 ce [2] ca e2 [2] e4 c0 [2] f0 db [2] ff c1 [2] e1 dc [2] e3 dd [2] f8 db [2] e4 dc [2] f8 f3 }

  condition:
    any of them
}