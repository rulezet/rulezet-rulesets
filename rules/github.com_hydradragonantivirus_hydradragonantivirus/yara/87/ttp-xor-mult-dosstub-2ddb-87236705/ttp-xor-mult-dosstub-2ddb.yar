rule TTP_XOR_MULT_DOSStub_2ddb {
  strings:
    $key_2ddb = { 79 b3 [2] 0d ab [2] 4a a9 [2] 0d b8 [2] 43 b4 [2] 4f be [2] 58 b5 [2] 43 fb [2] 7e }

  condition:
    any of them
}