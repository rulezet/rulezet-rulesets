rule TTP_XOR_MULT_DOSStub_f0bb {
  strings:
    $key_f0bb = { a4 d3 [2] d0 cb [2] 97 c9 [2] d0 d8 [2] 9e d4 [2] 92 de [2] 85 d5 [2] 9e 9b [2] a3 }

  condition:
    any of them
}