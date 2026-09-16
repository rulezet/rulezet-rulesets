rule TTP_XOR_MULT_DOSStub_2994 {
  strings:
    $key_2994 = { 7d fc [2] 09 e4 [2] 4e e6 [2] 09 f7 [2] 47 fb [2] 4b f1 [2] 5c fa [2] 47 b4 [2] 7a }

  condition:
    any of them
}