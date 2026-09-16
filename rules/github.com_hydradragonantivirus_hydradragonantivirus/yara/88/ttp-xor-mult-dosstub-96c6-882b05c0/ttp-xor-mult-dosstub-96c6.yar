rule TTP_XOR_MULT_DOSStub_96c6 {
  strings:
    $key_96c6 = { c2 ae [2] b6 b6 [2] f1 b4 [2] b6 a5 [2] f8 a9 [2] f4 a3 [2] e3 a8 [2] f8 e6 [2] c5 }

  condition:
    any of them
}