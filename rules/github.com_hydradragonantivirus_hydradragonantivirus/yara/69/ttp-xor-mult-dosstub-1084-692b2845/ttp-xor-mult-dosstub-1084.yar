rule TTP_XOR_MULT_DOSStub_1084 {
  strings:
    $key_1084 = { 44 ec [2] 30 f4 [2] 77 f6 [2] 30 e7 [2] 7e eb [2] 72 e1 [2] 65 ea [2] 7e a4 [2] 43 }

  condition:
    any of them
}