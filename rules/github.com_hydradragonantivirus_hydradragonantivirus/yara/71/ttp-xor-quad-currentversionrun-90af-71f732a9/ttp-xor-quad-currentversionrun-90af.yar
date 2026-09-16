rule TTP_XOR_QUAD_CurrentVersionRun_90af {
  strings:
    $key_90af = { c3 c0 [2] e7 ce [2] cc e2 [2] e2 c0 [2] f6 db [2] f9 c1 [2] e7 dc [2] e5 dd [2] fe db [2] e2 dc [2] fe f3 }

  condition:
    any of them
}