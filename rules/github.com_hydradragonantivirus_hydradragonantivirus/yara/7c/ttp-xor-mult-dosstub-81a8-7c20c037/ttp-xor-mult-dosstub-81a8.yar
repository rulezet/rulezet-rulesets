rule TTP_XOR_MULT_DOSStub_81a8 {
  strings:
    $key_81a8 = { d5 c0 [2] a1 d8 [2] e6 da [2] a1 cb [2] ef c7 [2] e3 cd [2] f4 c6 [2] ef 88 [2] d2 }

  condition:
    any of them
}