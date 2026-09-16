rule TTP_XOR_QUAD_CurrentVersionRun_92af {
  strings:
    $key_92af = { c1 c0 [2] e5 ce [2] ce e2 [2] e0 c0 [2] f4 db [2] fb c1 [2] e5 dc [2] e7 dd [2] fc db [2] e0 dc [2] fc f3 }

  condition:
    any of them
}