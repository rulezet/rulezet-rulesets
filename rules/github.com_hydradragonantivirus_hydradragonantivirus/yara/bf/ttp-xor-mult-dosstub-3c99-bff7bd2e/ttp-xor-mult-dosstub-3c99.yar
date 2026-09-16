rule TTP_XOR_MULT_DOSStub_3c99 {
  strings:
    $key_3c99 = { 68 f1 [2] 1c e9 [2] 5b eb [2] 1c fa [2] 52 f6 [2] 5e fc [2] 49 f7 [2] 52 b9 [2] 6f }

  condition:
    any of them
}