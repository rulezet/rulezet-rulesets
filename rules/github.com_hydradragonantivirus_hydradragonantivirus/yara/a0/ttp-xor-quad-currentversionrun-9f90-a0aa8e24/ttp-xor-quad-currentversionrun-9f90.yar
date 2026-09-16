rule TTP_XOR_QUAD_CurrentVersionRun_9f90 {
  strings:
    $key_9f90 = { cc ff [2] e8 f1 [2] c3 dd [2] ed ff [2] f9 e4 [2] f6 fe [2] e8 e3 [2] ea e2 [2] f1 e4 [2] ed e3 [2] f1 cc }

  condition:
    any of them
}