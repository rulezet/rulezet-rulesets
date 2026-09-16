rule TTP_XOR_MULT_DOSStub_fcdb {
  strings:
    $key_fcdb = { a8 b3 [2] dc ab [2] 9b a9 [2] dc b8 [2] 92 b4 [2] 9e be [2] 89 b5 [2] 92 fb [2] af }

  condition:
    any of them
}