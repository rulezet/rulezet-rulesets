rule TTP_XOR_MULT_DOSStub_dcd1 {
  strings:
    $key_dcd1 = { 88 b9 [2] fc a1 [2] bb a3 [2] fc b2 [2] b2 be [2] be b4 [2] a9 bf [2] b2 f1 [2] 8f }

  condition:
    any of them
}