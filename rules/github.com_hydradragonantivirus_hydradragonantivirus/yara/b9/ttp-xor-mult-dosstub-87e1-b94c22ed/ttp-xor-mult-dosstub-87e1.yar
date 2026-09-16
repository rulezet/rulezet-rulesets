rule TTP_XOR_MULT_DOSStub_87e1 {
  strings:
    $key_87e1 = { d3 89 [2] a7 91 [2] e0 93 [2] a7 82 [2] e9 8e [2] e5 84 [2] f2 8f [2] e9 c1 [2] d4 }

  condition:
    any of them
}