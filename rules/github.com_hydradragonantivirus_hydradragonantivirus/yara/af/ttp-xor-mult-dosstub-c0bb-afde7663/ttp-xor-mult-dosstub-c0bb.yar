rule TTP_XOR_MULT_DOSStub_c0bb {
  strings:
    $key_c0bb = { 94 d3 [2] e0 cb [2] a7 c9 [2] e0 d8 [2] ae d4 [2] a2 de [2] b5 d5 [2] ae 9b [2] 93 }

  condition:
    any of them
}