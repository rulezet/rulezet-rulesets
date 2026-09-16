rule TTP_XOR_QUAD_CurrentVersionRun_82a9 {
  strings:
    $key_82a9 = { d1 c6 [2] f5 c8 [2] de e4 [2] f0 c6 [2] e4 dd [2] eb c7 [2] f5 da [2] f7 db [2] ec dd [2] f0 da [2] ec f5 }

  condition:
    any of them
}