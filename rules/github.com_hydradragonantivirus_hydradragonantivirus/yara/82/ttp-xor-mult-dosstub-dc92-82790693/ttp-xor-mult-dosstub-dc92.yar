rule TTP_XOR_MULT_DOSStub_dc92 {
  strings:
    $key_dc92 = { 88 fa [2] fc e2 [2] bb e0 [2] fc f1 [2] b2 fd [2] be f7 [2] a9 fc [2] b2 b2 [2] 8f }

  condition:
    any of them
}