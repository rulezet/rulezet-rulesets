rule TTP_XOR_MULT_DOSStub_87f6 {
  strings:
    $key_87f6 = { d3 9e [2] a7 86 [2] e0 84 [2] a7 95 [2] e9 99 [2] e5 93 [2] f2 98 [2] e9 d6 [2] d4 }

  condition:
    any of them
}