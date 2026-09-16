rule TTP_XOR_MULT_DOSStub_d8a2 {
  strings:
    $key_d8a2 = { 8c ca [2] f8 d2 [2] bf d0 [2] f8 c1 [2] b6 cd [2] ba c7 [2] ad cc [2] b6 82 [2] 8b }

  condition:
    any of them
}