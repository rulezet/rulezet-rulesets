rule TTP_XOR_MULT_DOSStub_1e84 {
  strings:
    $key_1e84 = { 4a ec [2] 3e f4 [2] 79 f6 [2] 3e e7 [2] 70 eb [2] 7c e1 [2] 6b ea [2] 70 a4 [2] 4d }

  condition:
    any of them
}