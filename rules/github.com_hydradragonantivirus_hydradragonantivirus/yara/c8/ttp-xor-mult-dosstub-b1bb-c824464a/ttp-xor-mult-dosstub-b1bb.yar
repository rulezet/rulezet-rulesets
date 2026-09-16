rule TTP_XOR_MULT_DOSStub_b1bb {
  strings:
    $key_b1bb = { e5 d3 [2] 91 cb [2] d6 c9 [2] 91 d8 [2] df d4 [2] d3 de [2] c4 d5 [2] df 9b [2] e2 }

  condition:
    any of them
}