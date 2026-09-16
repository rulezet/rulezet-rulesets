rule TTP_XOR_MULT_DOSStub_b7bb {
  strings:
    $key_b7bb = { e3 d3 [2] 97 cb [2] d0 c9 [2] 97 d8 [2] d9 d4 [2] d5 de [2] c2 d5 [2] d9 9b [2] e4 }

  condition:
    any of them
}