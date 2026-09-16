rule TTP_XOR_MULT_DOSStub_d7c0 {
  strings:
    $key_d7c0 = { 83 a8 [2] f7 b0 [2] b0 b2 [2] f7 a3 [2] b9 af [2] b5 a5 [2] a2 ae [2] b9 e0 [2] 84 }

  condition:
    any of them
}