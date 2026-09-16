rule TTP_XOR_MULT_DOSStub_87f0 {
  strings:
    $key_87f0 = { d3 98 [2] a7 80 [2] e0 82 [2] a7 93 [2] e9 9f [2] e5 95 [2] f2 9e [2] e9 d0 [2] d4 }

  condition:
    any of them
}