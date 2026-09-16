rule TTP_XOR_MULT_DOSStub_91b0 {
  strings:
    $key_91b0 = { c5 d8 [2] b1 c0 [2] f6 c2 [2] b1 d3 [2] ff df [2] f3 d5 [2] e4 de [2] ff 90 [2] c2 }

  condition:
    any of them
}