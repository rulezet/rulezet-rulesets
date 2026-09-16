rule TTP_XOR_MULT_DOSStub_1c99 {
  strings:
    $key_1c99 = { 48 f1 [2] 3c e9 [2] 7b eb [2] 3c fa [2] 72 f6 [2] 7e fc [2] 69 f7 [2] 72 b9 [2] 4f }

  condition:
    any of them
}