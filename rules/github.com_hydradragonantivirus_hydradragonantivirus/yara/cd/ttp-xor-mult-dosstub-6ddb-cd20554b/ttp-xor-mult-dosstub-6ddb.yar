rule TTP_XOR_MULT_DOSStub_6ddb {
  strings:
    $key_6ddb = { 39 b3 [2] 4d ab [2] 0a a9 [2] 4d b8 [2] 03 b4 [2] 0f be [2] 18 b5 [2] 03 fb [2] 3e }

  condition:
    any of them
}