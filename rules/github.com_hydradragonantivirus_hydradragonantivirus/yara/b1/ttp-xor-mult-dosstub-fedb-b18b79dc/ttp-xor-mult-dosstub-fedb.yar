rule TTP_XOR_MULT_DOSStub_fedb {
  strings:
    $key_fedb = { aa b3 [2] de ab [2] 99 a9 [2] de b8 [2] 90 b4 [2] 9c be [2] 8b b5 [2] 90 fb [2] ad }

  condition:
    any of them
}