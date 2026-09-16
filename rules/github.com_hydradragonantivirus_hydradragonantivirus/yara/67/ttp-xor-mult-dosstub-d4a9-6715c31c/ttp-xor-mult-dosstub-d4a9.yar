rule TTP_XOR_MULT_DOSStub_d4a9 {
  strings:
    $key_d4a9 = { 80 c1 [2] f4 d9 [2] b3 db [2] f4 ca [2] ba c6 [2] b6 cc [2] a1 c7 [2] ba 89 [2] 87 }

  condition:
    any of them
}