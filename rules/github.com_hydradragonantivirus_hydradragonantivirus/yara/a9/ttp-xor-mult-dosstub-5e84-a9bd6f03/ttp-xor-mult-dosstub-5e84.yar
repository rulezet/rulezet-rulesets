rule TTP_XOR_MULT_DOSStub_5e84 {
  strings:
    $key_5e84 = { 0a ec [2] 7e f4 [2] 39 f6 [2] 7e e7 [2] 30 eb [2] 3c e1 [2] 2b ea [2] 30 a4 [2] 0d }

  condition:
    any of them
}