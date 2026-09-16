rule TTP_XOR_MULT_DOSStub_86f6 {
  strings:
    $key_86f6 = { d2 9e [2] a6 86 [2] e1 84 [2] a6 95 [2] e8 99 [2] e4 93 [2] f3 98 [2] e8 d6 [2] d5 }

  condition:
    any of them
}