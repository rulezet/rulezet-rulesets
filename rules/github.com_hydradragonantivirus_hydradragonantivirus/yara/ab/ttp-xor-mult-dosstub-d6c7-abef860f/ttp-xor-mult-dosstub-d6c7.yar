rule TTP_XOR_MULT_DOSStub_d6c7 {
  strings:
    $key_d6c7 = { 82 af [2] f6 b7 [2] b1 b5 [2] f6 a4 [2] b8 a8 [2] b4 a2 [2] a3 a9 [2] b8 e7 [2] 85 }

  condition:
    any of them
}