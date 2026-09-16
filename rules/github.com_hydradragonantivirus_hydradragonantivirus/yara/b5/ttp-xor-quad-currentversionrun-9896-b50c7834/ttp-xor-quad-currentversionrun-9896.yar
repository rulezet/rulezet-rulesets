rule TTP_XOR_QUAD_CurrentVersionRun_9896 {
  strings:
    $key_9896 = { cb f9 [2] ef f7 [2] c4 db [2] ea f9 [2] fe e2 [2] f1 f8 [2] ef e5 [2] ed e4 [2] f6 e2 [2] ea e5 [2] f6 ca }

  condition:
    any of them
}