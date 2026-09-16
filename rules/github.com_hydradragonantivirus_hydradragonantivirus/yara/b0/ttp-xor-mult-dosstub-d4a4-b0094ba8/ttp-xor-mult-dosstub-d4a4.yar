rule TTP_XOR_MULT_DOSStub_d4a4 {
  strings:
    $key_d4a4 = { 80 cc [2] f4 d4 [2] b3 d6 [2] f4 c7 [2] ba cb [2] b6 c1 [2] a1 ca [2] ba 84 [2] 87 }

  condition:
    any of them
}