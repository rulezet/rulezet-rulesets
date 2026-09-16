rule TTP_XOR_MULT_DOSStub_91bb {
  strings:
    $key_91bb = { c5 d3 [2] b1 cb [2] f6 c9 [2] b1 d8 [2] ff d4 [2] f3 de [2] e4 d5 [2] ff 9b [2] c2 }

  condition:
    any of them
}