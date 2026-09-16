rule TTP_XOR_MULT_DOSStub_2fdb {
  strings:
    $key_2fdb = { 7b b3 [2] 0f ab [2] 48 a9 [2] 0f b8 [2] 41 b4 [2] 4d be [2] 5a b5 [2] 41 fb [2] 7c }

  condition:
    any of them
}