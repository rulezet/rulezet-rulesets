rule TTP_XOR_MULT_DOSStub_3ddb {
  strings:
    $key_3ddb = { 69 b3 [2] 1d ab [2] 5a a9 [2] 1d b8 [2] 53 b4 [2] 5f be [2] 48 b5 [2] 53 fb [2] 6e }

  condition:
    any of them
}