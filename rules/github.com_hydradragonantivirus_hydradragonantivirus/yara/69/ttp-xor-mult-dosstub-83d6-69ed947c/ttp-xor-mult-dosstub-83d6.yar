rule TTP_XOR_MULT_DOSStub_83d6 {
  strings:
    $key_83d6 = { d7 be [2] a3 a6 [2] e4 a4 [2] a3 b5 [2] ed b9 [2] e1 b3 [2] f6 b8 [2] ed f6 [2] d0 }

  condition:
    any of them
}