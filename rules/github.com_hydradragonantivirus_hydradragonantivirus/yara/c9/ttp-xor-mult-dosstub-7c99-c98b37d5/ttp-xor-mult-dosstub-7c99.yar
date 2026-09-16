rule TTP_XOR_MULT_DOSStub_7c99 {
  strings:
    $key_7c99 = { 28 f1 [2] 5c e9 [2] 1b eb [2] 5c fa [2] 12 f6 [2] 1e fc [2] 09 f7 [2] 12 b9 [2] 2f }

  condition:
    any of them
}