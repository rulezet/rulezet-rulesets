rule TTP_XOR_MULT_DOSStub_d7a4 {
  strings:
    $key_d7a4 = { 83 cc [2] f7 d4 [2] b0 d6 [2] f7 c7 [2] b9 cb [2] b5 c1 [2] a2 ca [2] b9 84 [2] 84 }

  condition:
    any of them
}