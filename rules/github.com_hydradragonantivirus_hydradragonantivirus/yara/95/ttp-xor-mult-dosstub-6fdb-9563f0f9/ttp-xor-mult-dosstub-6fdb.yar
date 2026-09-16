rule TTP_XOR_MULT_DOSStub_6fdb {
  strings:
    $key_6fdb = { 3b b3 [2] 4f ab [2] 08 a9 [2] 4f b8 [2] 01 b4 [2] 0d be [2] 1a b5 [2] 01 fb [2] 3c }

  condition:
    any of them
}