rule TTP_XOR_MULT_DOSStub_d4c0 {
  strings:
    $key_d4c0 = { 80 a8 [2] f4 b0 [2] b3 b2 [2] f4 a3 [2] ba af [2] b6 a5 [2] a1 ae [2] ba e0 [2] 87 }

  condition:
    any of them
}