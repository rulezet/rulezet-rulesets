rule TTP_XOR_MULT_DOSStub_dcdb {
  strings:
    $key_dcdb = { 88 b3 [2] fc ab [2] bb a9 [2] fc b8 [2] b2 b4 [2] be be [2] a9 b5 [2] b2 fb [2] 8f }

  condition:
    any of them
}