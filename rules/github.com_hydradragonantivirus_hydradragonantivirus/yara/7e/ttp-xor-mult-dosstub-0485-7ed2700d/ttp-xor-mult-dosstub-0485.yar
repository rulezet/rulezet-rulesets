rule TTP_XOR_MULT_DOSStub_0485 {
  strings:
    $key_0485 = { 50 ed [2] 24 f5 [2] 63 f7 [2] 24 e6 [2] 6a ea [2] 66 e0 [2] 71 eb [2] 6a a5 [2] 57 }

  condition:
    any of them
}