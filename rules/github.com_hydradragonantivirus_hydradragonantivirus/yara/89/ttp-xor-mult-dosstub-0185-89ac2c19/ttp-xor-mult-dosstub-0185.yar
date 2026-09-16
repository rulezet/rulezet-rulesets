rule TTP_XOR_MULT_DOSStub_0185 {
  strings:
    $key_0185 = { 55 ed [2] 21 f5 [2] 66 f7 [2] 21 e6 [2] 6f ea [2] 63 e0 [2] 74 eb [2] 6f a5 [2] 52 }

  condition:
    any of them
}