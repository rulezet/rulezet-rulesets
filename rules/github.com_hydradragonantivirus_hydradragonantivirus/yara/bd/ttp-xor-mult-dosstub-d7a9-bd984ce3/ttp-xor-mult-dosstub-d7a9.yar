rule TTP_XOR_MULT_DOSStub_d7a9 {
  strings:
    $key_d7a9 = { 83 c1 [2] f7 d9 [2] b0 db [2] f7 ca [2] b9 c6 [2] b5 cc [2] a2 c7 [2] b9 89 [2] 84 }

  condition:
    any of them
}