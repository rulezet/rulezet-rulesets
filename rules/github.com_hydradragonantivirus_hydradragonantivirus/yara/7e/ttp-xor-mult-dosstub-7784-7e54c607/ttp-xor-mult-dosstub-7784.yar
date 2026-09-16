rule TTP_XOR_MULT_DOSStub_7784 {
  strings:
    $key_7784 = { 23 ec [2] 57 f4 [2] 10 f6 [2] 57 e7 [2] 19 eb [2] 15 e1 [2] 02 ea [2] 19 a4 [2] 24 }

  condition:
    any of them
}