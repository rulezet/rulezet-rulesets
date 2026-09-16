rule TTP_XOR_MULT_DOSStub_dedb {
  strings:
    $key_dedb = { 8a b3 [2] fe ab [2] b9 a9 [2] fe b8 [2] b0 b4 [2] bc be [2] ab b5 [2] b0 fb [2] 8d }

  condition:
    any of them
}