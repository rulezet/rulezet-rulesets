rule TTP_XOR_MULT_DOSStub_4684 {
  strings:
    $key_4684 = { 12 ec [2] 66 f4 [2] 21 f6 [2] 66 e7 [2] 28 eb [2] 24 e1 [2] 33 ea [2] 28 a4 [2] 15 }

  condition:
    any of them
}