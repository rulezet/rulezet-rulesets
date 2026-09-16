rule TTP_XOR_MULT_DOSStub_4185 {
  strings:
    $key_4185 = { 15 ed [2] 61 f5 [2] 26 f7 [2] 61 e6 [2] 2f ea [2] 23 e0 [2] 34 eb [2] 2f a5 [2] 12 }

  condition:
    any of them
}