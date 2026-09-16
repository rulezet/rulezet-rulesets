rule TTP_XOR_QUAD_CurrentVersionRun_9897 {
  strings:
    $key_9897 = { cb f8 [2] ef f6 [2] c4 da [2] ea f8 [2] fe e3 [2] f1 f9 [2] ef e4 [2] ed e5 [2] f6 e3 [2] ea e4 [2] f6 cb }

  condition:
    any of them
}