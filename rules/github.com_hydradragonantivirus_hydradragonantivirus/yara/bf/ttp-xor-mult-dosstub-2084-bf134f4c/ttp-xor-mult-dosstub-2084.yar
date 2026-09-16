rule TTP_XOR_MULT_DOSStub_2084 {
  strings:
    $key_2084 = { 74 ec [2] 00 f4 [2] 47 f6 [2] 00 e7 [2] 4e eb [2] 42 e1 [2] 55 ea [2] 4e a4 [2] 73 }

  condition:
    any of them
}