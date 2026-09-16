rule TTP_XOR_MULT_DOSStub_dcd0 {
  strings:
    $key_dcd0 = { 88 b8 [2] fc a0 [2] bb a2 [2] fc b3 [2] b2 bf [2] be b5 [2] a9 be [2] b2 f0 [2] 8f }

  condition:
    any of them
}