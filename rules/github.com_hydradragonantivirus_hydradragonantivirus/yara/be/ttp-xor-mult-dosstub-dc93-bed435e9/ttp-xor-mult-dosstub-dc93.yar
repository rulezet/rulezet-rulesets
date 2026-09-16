rule TTP_XOR_MULT_DOSStub_dc93 {
  strings:
    $key_dc93 = { 88 fb [2] fc e3 [2] bb e1 [2] fc f0 [2] b2 fc [2] be f6 [2] a9 fd [2] b2 b3 [2] 8f }

  condition:
    any of them
}