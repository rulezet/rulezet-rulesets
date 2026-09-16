rule TTP_XOR_MULT_DOSStub_5c99 {
  strings:
    $key_5c99 = { 08 f1 [2] 7c e9 [2] 3b eb [2] 7c fa [2] 32 f6 [2] 3e fc [2] 29 f7 [2] 32 b9 [2] 0f }

  condition:
    any of them
}