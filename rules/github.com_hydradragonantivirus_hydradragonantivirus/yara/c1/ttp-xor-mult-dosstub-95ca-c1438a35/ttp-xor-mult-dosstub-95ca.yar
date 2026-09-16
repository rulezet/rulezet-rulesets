rule TTP_XOR_MULT_DOSStub_95ca {
  strings:
    $key_95ca = { c1 a2 [2] b5 ba [2] f2 b8 [2] b5 a9 [2] fb a5 [2] f7 af [2] e0 a4 [2] fb ea [2] c6 }

  condition:
    any of them
}