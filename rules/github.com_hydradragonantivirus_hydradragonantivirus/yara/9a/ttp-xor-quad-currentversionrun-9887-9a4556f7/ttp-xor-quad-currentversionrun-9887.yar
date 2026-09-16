rule TTP_XOR_QUAD_CurrentVersionRun_9887 {
  strings:
    $key_9887 = { cb e8 [2] ef e6 [2] c4 ca [2] ea e8 [2] fe f3 [2] f1 e9 [2] ef f4 [2] ed f5 [2] f6 f3 [2] ea f4 [2] f6 db }

  condition:
    any of them
}