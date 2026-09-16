rule TTP_XOR_MULT_DOSStub_5684 {
  strings:
    $key_5684 = { 02 ec [2] 76 f4 [2] 31 f6 [2] 76 e7 [2] 38 eb [2] 34 e1 [2] 23 ea [2] 38 a4 [2] 05 }

  condition:
    any of them
}