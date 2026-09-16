rule TTP_XOR_MULT_DOSStub_95e4 {
  strings:
    $key_95e4 = { c1 8c [2] b5 94 [2] f2 96 [2] b5 87 [2] fb 8b [2] f7 81 [2] e0 8a [2] fb c4 [2] c6 }

  condition:
    any of them
}