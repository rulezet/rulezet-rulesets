rule TTP_XOR_MULT_DOSStub_91d4 {
  strings:
    $key_91d4 = { c5 bc [2] b1 a4 [2] f6 a6 [2] b1 b7 [2] ff bb [2] f3 b1 [2] e4 ba [2] ff f4 [2] c2 }

  condition:
    any of them
}