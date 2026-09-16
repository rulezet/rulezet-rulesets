rule TTP_XOR_MULT_DOSStub_91b9 {
  strings:
    $key_91b9 = { c5 d1 [2] b1 c9 [2] f6 cb [2] b1 da [2] ff d6 [2] f3 dc [2] e4 d7 [2] ff 99 [2] c2 }

  condition:
    any of them
}