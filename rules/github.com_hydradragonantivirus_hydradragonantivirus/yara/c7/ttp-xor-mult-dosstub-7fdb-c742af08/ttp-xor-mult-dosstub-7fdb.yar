rule TTP_XOR_MULT_DOSStub_7fdb {
  strings:
    $key_7fdb = { 2b b3 [2] 5f ab [2] 18 a9 [2] 5f b8 [2] 11 b4 [2] 1d be [2] 0a b5 [2] 11 fb [2] 2c }

  condition:
    any of them
}