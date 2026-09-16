rule TTP_XOR_MULT_DOSStub_e2bb {
  strings:
    $key_e2bb = { b6 d3 [2] c2 cb [2] 85 c9 [2] c2 d8 [2] 8c d4 [2] 80 de [2] 97 d5 [2] 8c 9b [2] b1 }

  condition:
    any of them
}