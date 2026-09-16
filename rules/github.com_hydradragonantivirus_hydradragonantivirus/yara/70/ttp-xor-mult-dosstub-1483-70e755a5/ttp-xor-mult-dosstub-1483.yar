rule TTP_XOR_MULT_DOSStub_1483 {
  strings:
    $key_1483 = { 40 eb [2] 34 f3 [2] 73 f1 [2] 34 e0 [2] 7a ec [2] 76 e6 [2] 61 ed [2] 7a a3 [2] 47 }

  condition:
    any of them
}