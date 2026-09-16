rule TTP_XOR_MULT_DOSStub_2c99 {
  strings:
    $key_2c99 = { 78 f1 [2] 0c e9 [2] 4b eb [2] 0c fa [2] 42 f6 [2] 4e fc [2] 59 f7 [2] 42 b9 [2] 7f }

  condition:
    any of them
}