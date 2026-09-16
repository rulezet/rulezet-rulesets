rule TTP_XOR_MULT_DOSStub_6cdb {
  strings:
    $key_6cdb = { 38 b3 [2] 4c ab [2] 0b a9 [2] 4c b8 [2] 02 b4 [2] 0e be [2] 19 b5 [2] 02 fb [2] 3f }

  condition:
    any of them
}