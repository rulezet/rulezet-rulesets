rule TTP_XOR_MULT_DOSStub_5e83 {
  strings:
    $key_5e83 = { 0a eb [2] 7e f3 [2] 39 f1 [2] 7e e0 [2] 30 ec [2] 3c e6 [2] 2b ed [2] 30 a3 [2] 0d }

  condition:
    any of them
}