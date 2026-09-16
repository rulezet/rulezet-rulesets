rule TTP_XOR_MULT_DOSStub_c486 {
  strings:
    $key_c486 = { 90 ee [2] e4 f6 [2] a3 f4 [2] e4 e5 [2] aa e9 [2] a6 e3 [2] b1 e8 [2] aa a6 [2] 97 }

  condition:
    any of them
}