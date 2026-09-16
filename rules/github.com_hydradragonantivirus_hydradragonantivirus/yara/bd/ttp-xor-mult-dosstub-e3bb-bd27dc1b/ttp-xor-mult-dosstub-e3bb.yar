rule TTP_XOR_MULT_DOSStub_e3bb {
  strings:
    $key_e3bb = { b7 d3 [2] c3 cb [2] 84 c9 [2] c3 d8 [2] 8d d4 [2] 81 de [2] 96 d5 [2] 8d 9b [2] b0 }

  condition:
    any of them
}