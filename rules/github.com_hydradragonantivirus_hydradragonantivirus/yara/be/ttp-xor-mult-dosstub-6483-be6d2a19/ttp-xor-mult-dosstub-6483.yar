rule TTP_XOR_MULT_DOSStub_6483 {
  strings:
    $key_6483 = { 30 eb [2] 44 f3 [2] 03 f1 [2] 44 e0 [2] 0a ec [2] 06 e6 [2] 11 ed [2] 0a a3 [2] 37 }

  condition:
    any of them
}