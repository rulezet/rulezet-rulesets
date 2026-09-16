rule TTP_XOR_MULT_DOSStub_95c6 {
  strings:
    $key_95c6 = { c1 ae [2] b5 b6 [2] f2 b4 [2] b5 a5 [2] fb a9 [2] f7 a3 [2] e0 a8 [2] fb e6 [2] c6 }

  condition:
    any of them
}