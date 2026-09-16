rule TTP_XOR_MULT_DOSStub_ecdb {
  strings:
    $key_ecdb = { b8 b3 [2] cc ab [2] 8b a9 [2] cc b8 [2] 82 b4 [2] 8e be [2] 99 b5 [2] 82 fb [2] bf }

  condition:
    any of them
}