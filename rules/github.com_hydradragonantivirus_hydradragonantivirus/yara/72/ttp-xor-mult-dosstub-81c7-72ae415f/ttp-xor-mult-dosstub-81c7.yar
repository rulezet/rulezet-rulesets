rule TTP_XOR_MULT_DOSStub_81c7 {
  strings:
    $key_81c7 = { d5 af [2] a1 b7 [2] e6 b5 [2] a1 a4 [2] ef a8 [2] e3 a2 [2] f4 a9 [2] ef e7 [2] d2 }

  condition:
    any of them
}