rule TTP_XOR_MULT_DOSStub_ab92 {
  strings:
    $key_ab92 = { ff fa [2] 8b e2 [2] cc e0 [2] 8b f1 [2] c5 fd [2] c9 f7 [2] de fc [2] c5 b2 [2] f8 }

  condition:
    any of them
}