rule TTP_XOR_MULT_DOSStub_d0a9 {
  strings:
    $key_d0a9 = { 84 c1 [2] f0 d9 [2] b7 db [2] f0 ca [2] be c6 [2] b2 cc [2] a5 c7 [2] be 89 [2] 83 }

  condition:
    any of them
}