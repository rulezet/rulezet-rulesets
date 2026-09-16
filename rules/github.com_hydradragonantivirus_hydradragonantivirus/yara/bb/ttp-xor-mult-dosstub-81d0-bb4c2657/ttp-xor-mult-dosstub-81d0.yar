rule TTP_XOR_MULT_DOSStub_81d0 {
  strings:
    $key_81d0 = { d5 b8 [2] a1 a0 [2] e6 a2 [2] a1 b3 [2] ef bf [2] e3 b5 [2] f4 be [2] ef f0 [2] d2 }

  condition:
    any of them
}