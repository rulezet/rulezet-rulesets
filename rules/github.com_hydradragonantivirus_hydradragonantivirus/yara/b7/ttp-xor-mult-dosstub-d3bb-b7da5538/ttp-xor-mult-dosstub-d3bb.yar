rule TTP_XOR_MULT_DOSStub_d3bb {
  strings:
    $key_d3bb = { 87 d3 [2] f3 cb [2] b4 c9 [2] f3 d8 [2] bd d4 [2] b1 de [2] a6 d5 [2] bd 9b [2] 80 }

  condition:
    any of them
}