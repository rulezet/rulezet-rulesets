rule TTP_XOR_MULT_DOSStub_4483 {
  strings:
    $key_4483 = { 10 eb [2] 64 f3 [2] 23 f1 [2] 64 e0 [2] 2a ec [2] 26 e6 [2] 31 ed [2] 2a a3 [2] 17 }

  condition:
    any of them
}