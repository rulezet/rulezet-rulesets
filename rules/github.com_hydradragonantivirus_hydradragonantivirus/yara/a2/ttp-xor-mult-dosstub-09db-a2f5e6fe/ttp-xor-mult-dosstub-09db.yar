rule TTP_XOR_MULT_DOSStub_09db {
  strings:
    $key_09db = { 5d b3 [2] 29 ab [2] 6e a9 [2] 29 b8 [2] 67 b4 [2] 6b be [2] 7c b5 [2] 67 fb [2] 5a }

  condition:
    any of them
}