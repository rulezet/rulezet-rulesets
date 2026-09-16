rule TTP_XOR_MULT_DOSStub_86f1 {
  strings:
    $key_86f1 = { d2 99 [2] a6 81 [2] e1 83 [2] a6 92 [2] e8 9e [2] e4 94 [2] f3 9f [2] e8 d1 [2] d5 }

  condition:
    any of them
}