rule TTP_XOR_MULT_DOSStub_d4b4 {
  strings:
    $key_d4b4 = { 80 dc [2] f4 c4 [2] b3 c6 [2] f4 d7 [2] ba db [2] b6 d1 [2] a1 da [2] ba 94 [2] 87 }

  condition:
    any of them
}