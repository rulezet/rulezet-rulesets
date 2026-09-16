rule TTP_XOR_MULT_DOSStub_4ddb {
  strings:
    $key_4ddb = { 19 b3 [2] 6d ab [2] 2a a9 [2] 6d b8 [2] 23 b4 [2] 2f be [2] 38 b5 [2] 23 fb [2] 1e }

  condition:
    any of them
}