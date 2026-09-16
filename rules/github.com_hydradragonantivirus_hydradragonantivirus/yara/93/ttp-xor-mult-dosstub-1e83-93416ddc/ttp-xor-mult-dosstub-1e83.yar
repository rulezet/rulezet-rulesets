rule TTP_XOR_MULT_DOSStub_1e83 {
  strings:
    $key_1e83 = { 4a eb [2] 3e f3 [2] 79 f1 [2] 3e e0 [2] 70 ec [2] 7c e6 [2] 6b ed [2] 70 a3 [2] 4d }

  condition:
    any of them
}