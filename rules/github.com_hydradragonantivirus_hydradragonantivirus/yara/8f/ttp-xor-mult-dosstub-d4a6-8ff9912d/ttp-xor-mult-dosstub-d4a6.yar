rule TTP_XOR_MULT_DOSStub_d4a6 {
  strings:
    $key_d4a6 = { 80 ce [2] f4 d6 [2] b3 d4 [2] f4 c5 [2] ba c9 [2] b6 c3 [2] a1 c8 [2] ba 86 [2] 87 }

  condition:
    any of them
}