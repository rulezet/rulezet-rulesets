rule TTP_XOR_MULT_DOSStub_d8a5 {
  strings:
    $key_d8a5 = { 8c cd [2] f8 d5 [2] bf d7 [2] f8 c6 [2] b6 ca [2] ba c0 [2] ad cb [2] b6 85 [2] 8b }

  condition:
    any of them
}