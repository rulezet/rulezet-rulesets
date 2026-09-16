rule TTP_XOR_QUAD_CurrentVersionRun_9895 {
  strings:
    $key_9895 = { cb fa [2] ef f4 [2] c4 d8 [2] ea fa [2] fe e1 [2] f1 fb [2] ef e6 [2] ed e7 [2] f6 e1 [2] ea e6 [2] f6 c9 }

  condition:
    any of them
}