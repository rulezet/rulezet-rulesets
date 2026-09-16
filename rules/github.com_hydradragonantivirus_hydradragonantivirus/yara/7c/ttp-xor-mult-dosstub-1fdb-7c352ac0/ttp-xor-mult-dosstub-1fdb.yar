rule TTP_XOR_MULT_DOSStub_1fdb {
  strings:
    $key_1fdb = { 4b b3 [2] 3f ab [2] 78 a9 [2] 3f b8 [2] 71 b4 [2] 7d be [2] 6a b5 [2] 71 fb [2] 4c }

  condition:
    any of them
}