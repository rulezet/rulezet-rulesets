rule TTP_XOR_MULT_DOSStub_e4bb {
  strings:
    $key_e4bb = { b0 d3 [2] c4 cb [2] 83 c9 [2] c4 d8 [2] 8a d4 [2] 86 de [2] 91 d5 [2] 8a 9b [2] b7 }

  condition:
    any of them
}