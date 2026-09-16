rule TTP_XOR_MULT_DOSStub_86c7 {
  strings:
    $key_86c7 = { d2 af [2] a6 b7 [2] e1 b5 [2] a6 a4 [2] e8 a8 [2] e4 a2 [2] f3 a9 [2] e8 e7 [2] d5 }

  condition:
    any of them
}