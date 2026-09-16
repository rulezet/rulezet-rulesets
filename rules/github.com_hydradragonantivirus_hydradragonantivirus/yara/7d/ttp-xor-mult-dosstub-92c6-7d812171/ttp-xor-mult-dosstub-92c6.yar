rule TTP_XOR_MULT_DOSStub_92c6 {
  strings:
    $key_92c6 = { c6 ae [2] b2 b6 [2] f5 b4 [2] b2 a5 [2] fc a9 [2] f0 a3 [2] e7 a8 [2] fc e6 [2] c1 }

  condition:
    any of them
}