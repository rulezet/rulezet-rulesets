rule TTP_XOR_QUAD_CurrentVersionRun_96a9 {
  strings:
    $key_96a9 = { c5 c6 [2] e1 c8 [2] ca e4 [2] e4 c6 [2] f0 dd [2] ff c7 [2] e1 da [2] e3 db [2] f8 dd [2] e4 da [2] f8 f5 }

  condition:
    any of them
}