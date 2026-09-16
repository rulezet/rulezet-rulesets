rule TTP_XOR_MULT_DOSStub_86c6 {
  strings:
    $key_86c6 = { d2 ae [2] a6 b6 [2] e1 b4 [2] a6 a5 [2] e8 a9 [2] e4 a3 [2] f3 a8 [2] e8 e6 [2] d5 }

  condition:
    any of them
}