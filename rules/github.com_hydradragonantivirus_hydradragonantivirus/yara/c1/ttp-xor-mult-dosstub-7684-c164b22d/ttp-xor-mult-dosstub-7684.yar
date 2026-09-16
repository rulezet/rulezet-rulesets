rule TTP_XOR_MULT_DOSStub_7684 {
  strings:
    $key_7684 = { 22 ec [2] 56 f4 [2] 11 f6 [2] 56 e7 [2] 18 eb [2] 14 e1 [2] 03 ea [2] 18 a4 [2] 25 }

  condition:
    any of them
}