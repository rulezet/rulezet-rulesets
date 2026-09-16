rule TTP_XOR_MULT_DOSStub_3e83 {
  strings:
    $key_3e83 = { 6a eb [2] 1e f3 [2] 59 f1 [2] 1e e0 [2] 50 ec [2] 5c e6 [2] 4b ed [2] 50 a3 [2] 6d }

  condition:
    any of them
}