rule TTP_XOR_MULT_DOSStub_3cdb {
  strings:
    $key_3cdb = { 68 b3 [2] 1c ab [2] 5b a9 [2] 1c b8 [2] 52 b4 [2] 5e be [2] 49 b5 [2] 52 fb [2] 6f }

  condition:
    any of them
}