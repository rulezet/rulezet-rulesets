rule TTP_XOR_MULT_DOSStub_abc6 {
  strings:
    $key_abc6 = { ff ae [2] 8b b6 [2] cc b4 [2] 8b a5 [2] c5 a9 [2] c9 a3 [2] de a8 [2] c5 e6 [2] f8 }

  condition:
    any of them
}