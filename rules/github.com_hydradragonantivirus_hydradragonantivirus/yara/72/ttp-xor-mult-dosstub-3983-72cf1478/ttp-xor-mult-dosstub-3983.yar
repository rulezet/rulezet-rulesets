rule TTP_XOR_MULT_DOSStub_3983 {
  strings:
    $key_3983 = { 6d eb [2] 19 f3 [2] 5e f1 [2] 19 e0 [2] 57 ec [2] 5b e6 [2] 4c ed [2] 57 a3 [2] 6a }

  condition:
    any of them
}