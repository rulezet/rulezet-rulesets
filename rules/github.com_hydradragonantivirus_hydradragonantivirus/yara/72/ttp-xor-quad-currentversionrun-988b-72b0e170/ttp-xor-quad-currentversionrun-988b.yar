rule TTP_XOR_QUAD_CurrentVersionRun_988b {
  strings:
    $key_988b = { cb e4 [2] ef ea [2] c4 c6 [2] ea e4 [2] fe ff [2] f1 e5 [2] ef f8 [2] ed f9 [2] f6 ff [2] ea f8 [2] f6 d7 }

  condition:
    any of them
}