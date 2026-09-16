rule TTP_XOR_MULT_DOSStub_93b0 {
  strings:
    $key_93b0 = { c7 d8 [2] b3 c0 [2] f4 c2 [2] b3 d3 [2] fd df [2] f1 d5 [2] e6 de [2] fd 90 [2] c0 }

  condition:
    any of them
}