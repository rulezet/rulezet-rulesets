rule TTP_XOR_MULT_DOSStub_1ddb {
  strings:
    $key_1ddb = { 49 b3 [2] 3d ab [2] 7a a9 [2] 3d b8 [2] 73 b4 [2] 7f be [2] 68 b5 [2] 73 fb [2] 4e }

  condition:
    any of them
}