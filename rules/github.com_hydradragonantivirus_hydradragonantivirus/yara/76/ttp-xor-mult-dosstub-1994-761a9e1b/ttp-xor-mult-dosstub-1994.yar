rule TTP_XOR_MULT_DOSStub_1994 {
  strings:
    $key_1994 = { 4d fc [2] 39 e4 [2] 7e e6 [2] 39 f7 [2] 77 fb [2] 7b f1 [2] 6c fa [2] 77 b4 [2] 4a }

  condition:
    any of them
}