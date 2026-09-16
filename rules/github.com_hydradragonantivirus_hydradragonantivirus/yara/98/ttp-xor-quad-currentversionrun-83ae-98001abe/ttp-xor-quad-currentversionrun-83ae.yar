rule TTP_XOR_QUAD_CurrentVersionRun_83ae {
  strings:
    $key_83ae = { d0 c1 [2] f4 cf [2] df e3 [2] f1 c1 [2] e5 da [2] ea c0 [2] f4 dd [2] f6 dc [2] ed da [2] f1 dd [2] ed f2 }

  condition:
    any of them
}