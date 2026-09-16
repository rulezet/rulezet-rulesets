rule TTP_XOR_MULT_DOSStub_5994 {
  strings:
    $key_5994 = { 0d fc [2] 79 e4 [2] 3e e6 [2] 79 f7 [2] 37 fb [2] 3b f1 [2] 2c fa [2] 37 b4 [2] 0a }

  condition:
    any of them
}