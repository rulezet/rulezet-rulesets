rule TTP_XOR_MULT_DOSStub_c3bb {
  strings:
    $key_c3bb = { 97 d3 [2] e3 cb [2] a4 c9 [2] e3 d8 [2] ad d4 [2] a1 de [2] b6 d5 [2] ad 9b [2] 90 }

  condition:
    any of them
}