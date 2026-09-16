rule TTP_XOR_MULT_DOSStub_c5bb {
  strings:
    $key_c5bb = { 91 d3 [2] e5 cb [2] a2 c9 [2] e5 d8 [2] ab d4 [2] a7 de [2] b0 d5 [2] ab 9b [2] 96 }

  condition:
    any of them
}