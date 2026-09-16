rule TTP_XOR_MULT_DOSStub_86e4 {
  strings:
    $key_86e4 = { d2 8c [2] a6 94 [2] e1 96 [2] a6 87 [2] e8 8b [2] e4 81 [2] f3 8a [2] e8 c4 [2] d5 }

  condition:
    any of them
}