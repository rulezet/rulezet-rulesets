rule TTP_XOR_MULT_DOSStub_2cdb {
  strings:
    $key_2cdb = { 78 b3 [2] 0c ab [2] 4b a9 [2] 0c b8 [2] 42 b4 [2] 4e be [2] 59 b5 [2] 42 fb [2] 7f }

  condition:
    any of them
}