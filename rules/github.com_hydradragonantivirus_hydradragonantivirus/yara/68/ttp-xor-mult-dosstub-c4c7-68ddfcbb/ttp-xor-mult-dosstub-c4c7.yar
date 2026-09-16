rule TTP_XOR_MULT_DOSStub_c4c7 {
  strings:
    $key_c4c7 = { 90 af [2] e4 b7 [2] a3 b5 [2] e4 a4 [2] aa a8 [2] a6 a2 [2] b1 a9 [2] aa e7 [2] 97 }

  condition:
    any of them
}