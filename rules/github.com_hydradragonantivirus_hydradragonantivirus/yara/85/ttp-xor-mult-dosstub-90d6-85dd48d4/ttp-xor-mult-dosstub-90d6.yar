rule TTP_XOR_MULT_DOSStub_90d6 {
  strings:
    $key_90d6 = { c4 be [2] b0 a6 [2] f7 a4 [2] b0 b5 [2] fe b9 [2] f2 b3 [2] e5 b8 [2] fe f6 [2] c3 }

  condition:
    any of them
}