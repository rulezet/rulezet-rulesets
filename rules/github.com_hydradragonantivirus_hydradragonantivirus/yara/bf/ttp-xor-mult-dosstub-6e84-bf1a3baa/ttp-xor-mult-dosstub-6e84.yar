rule TTP_XOR_MULT_DOSStub_6e84 {
  strings:
    $key_6e84 = { 3a ec [2] 4e f4 [2] 09 f6 [2] 4e e7 [2] 00 eb [2] 0c e1 [2] 1b ea [2] 00 a4 [2] 3d }

  condition:
    any of them
}