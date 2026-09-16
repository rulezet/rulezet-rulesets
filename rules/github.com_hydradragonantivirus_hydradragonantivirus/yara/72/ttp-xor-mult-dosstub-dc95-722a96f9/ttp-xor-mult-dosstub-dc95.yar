rule TTP_XOR_MULT_DOSStub_dc95 {
  strings:
    $key_dc95 = { 88 fd [2] fc e5 [2] bb e7 [2] fc f6 [2] b2 fa [2] be f0 [2] a9 fb [2] b2 b5 [2] 8f }

  condition:
    any of them
}