rule TTP_XOR_MULT_DOSStub_9587 {
  strings:
    $key_9587 = { c1 ef [2] b5 f7 [2] f2 f5 [2] b5 e4 [2] fb e8 [2] f7 e2 [2] e0 e9 [2] fb a7 [2] c6 }

  condition:
    any of them
}