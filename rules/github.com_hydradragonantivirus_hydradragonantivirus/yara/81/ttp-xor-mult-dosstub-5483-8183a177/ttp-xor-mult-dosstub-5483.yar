rule TTP_XOR_MULT_DOSStub_5483 {
  strings:
    $key_5483 = { 00 eb [2] 74 f3 [2] 33 f1 [2] 74 e0 [2] 3a ec [2] 36 e6 [2] 21 ed [2] 3a a3 [2] 07 }

  condition:
    any of them
}