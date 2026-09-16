rule TTP_XOR_MULT_DOSStub_b6bb {
  strings:
    $key_b6bb = { e2 d3 [2] 96 cb [2] d1 c9 [2] 96 d8 [2] d8 d4 [2] d4 de [2] c3 d5 [2] d8 9b [2] e5 }

  condition:
    any of them
}