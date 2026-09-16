rule TTP_XOR_MULT_DOSStub_81d4 {
  strings:
    $key_81d4 = { d5 bc [2] a1 a4 [2] e6 a6 [2] a1 b7 [2] ef bb [2] e3 b1 [2] f4 ba [2] ef f4 [2] d2 }

  condition:
    any of them
}