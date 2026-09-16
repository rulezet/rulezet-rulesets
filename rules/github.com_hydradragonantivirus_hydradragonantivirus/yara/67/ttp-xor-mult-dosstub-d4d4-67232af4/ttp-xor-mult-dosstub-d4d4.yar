rule TTP_XOR_MULT_DOSStub_d4d4 {
  strings:
    $key_d4d4 = { 80 bc [2] f4 a4 [2] b3 a6 [2] f4 b7 [2] ba bb [2] b6 b1 [2] a1 ba [2] ba f4 [2] 87 }

  condition:
    any of them
}