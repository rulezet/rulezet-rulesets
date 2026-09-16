rule TTP_XOR_MULT_DOSStub_86e2 {
  strings:
    $key_86e2 = { d2 8a [2] a6 92 [2] e1 90 [2] a6 81 [2] e8 8d [2] e4 87 [2] f3 8c [2] e8 c2 [2] d5 }

  condition:
    any of them
}