rule TTP_XOR_QUAD_CurrentVersionRun_8ea9 {
  strings:
    $key_8ea9 = { dd c6 [2] f9 c8 [2] d2 e4 [2] fc c6 [2] e8 dd [2] e7 c7 [2] f9 da [2] fb db [2] e0 dd [2] fc da [2] e0 f5 }

  condition:
    any of them
}