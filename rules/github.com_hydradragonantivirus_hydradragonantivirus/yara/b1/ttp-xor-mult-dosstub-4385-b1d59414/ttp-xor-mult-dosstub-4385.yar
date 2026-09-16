rule TTP_XOR_MULT_DOSStub_4385 {
  strings:
    $key_4385 = { 17 ed [2] 63 f5 [2] 24 f7 [2] 63 e6 [2] 2d ea [2] 21 e0 [2] 36 eb [2] 2d a5 [2] 10 }

  condition:
    any of them
}