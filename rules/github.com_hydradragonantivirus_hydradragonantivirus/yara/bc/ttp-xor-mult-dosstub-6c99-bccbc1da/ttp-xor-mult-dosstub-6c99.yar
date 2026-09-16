rule TTP_XOR_MULT_DOSStub_6c99 {
  strings:
    $key_6c99 = { 38 f1 [2] 4c e9 [2] 0b eb [2] 4c fa [2] 02 f6 [2] 0e fc [2] 19 f7 [2] 02 b9 [2] 3f }

  condition:
    any of them
}