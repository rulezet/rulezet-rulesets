rule TTP_XOR_MULT_DOSStub_5cdb {
  strings:
    $key_5cdb = { 08 b3 [2] 7c ab [2] 3b a9 [2] 7c b8 [2] 32 b4 [2] 3e be [2] 29 b5 [2] 32 fb [2] 0f }

  condition:
    any of them
}