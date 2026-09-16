rule TTP_XOR_MULT_DOSStub_dcd6 {
  strings:
    $key_dcd6 = { 88 be [2] fc a6 [2] bb a4 [2] fc b5 [2] b2 b9 [2] be b3 [2] a9 b8 [2] b2 f6 [2] 8f }

  condition:
    any of them
}