rule TTP_XOR_MULT_DOSStub_e0bb {
  strings:
    $key_e0bb = { b4 d3 [2] c0 cb [2] 87 c9 [2] c0 d8 [2] 8e d4 [2] 82 de [2] 95 d5 [2] 8e 9b [2] b3 }

  condition:
    any of them
}