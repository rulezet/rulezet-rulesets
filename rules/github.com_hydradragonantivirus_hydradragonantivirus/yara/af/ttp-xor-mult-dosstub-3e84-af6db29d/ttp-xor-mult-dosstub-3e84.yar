rule TTP_XOR_MULT_DOSStub_3e84 {
  strings:
    $key_3e84 = { 6a ec [2] 1e f4 [2] 59 f6 [2] 1e e7 [2] 50 eb [2] 5c e1 [2] 4b ea [2] 50 a4 [2] 6d }

  condition:
    any of them
}