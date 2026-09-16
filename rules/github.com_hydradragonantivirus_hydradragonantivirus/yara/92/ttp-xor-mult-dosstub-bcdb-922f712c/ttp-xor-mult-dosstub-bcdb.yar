rule TTP_XOR_MULT_DOSStub_bcdb {
  strings:
    $key_bcdb = { e8 b3 [2] 9c ab [2] db a9 [2] 9c b8 [2] d2 b4 [2] de be [2] c9 b5 [2] d2 fb [2] ef }

  condition:
    any of them
}