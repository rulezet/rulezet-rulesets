rule TTP_XOR_MULT_DOSStub_4685 {
  strings:
    $key_4685 = { 12 ed [2] 66 f5 [2] 21 f7 [2] 66 e6 [2] 28 ea [2] 24 e0 [2] 33 eb [2] 28 a5 [2] 15 }

  condition:
    any of them
}