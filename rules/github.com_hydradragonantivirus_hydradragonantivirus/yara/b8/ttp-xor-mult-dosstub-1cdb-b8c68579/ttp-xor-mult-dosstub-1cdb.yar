rule TTP_XOR_MULT_DOSStub_1cdb {
  strings:
    $key_1cdb = { 48 b3 [2] 3c ab [2] 7b a9 [2] 3c b8 [2] 72 b4 [2] 7e be [2] 69 b5 [2] 72 fb [2] 4f }

  condition:
    any of them
}