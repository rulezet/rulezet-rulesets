rule TTP_XOR_MULT_DOSStub_f2bb {
  strings:
    $key_f2bb = { a6 d3 [2] d2 cb [2] 95 c9 [2] d2 d8 [2] 9c d4 [2] 90 de [2] 87 d5 [2] 9c 9b [2] a1 }

  condition:
    any of them
}