rule TTP_XOR_MULT_DOSStub_3483 {
  strings:
    $key_3483 = { 60 eb [2] 14 f3 [2] 53 f1 [2] 14 e0 [2] 5a ec [2] 56 e6 [2] 41 ed [2] 5a a3 [2] 67 }

  condition:
    any of them
}