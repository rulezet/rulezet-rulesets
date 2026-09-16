rule TTP_XOR_MULT_DOSStub_4388 {
  strings:
    $key_4388 = { 17 e0 [2] 63 f8 [2] 24 fa [2] 63 eb [2] 2d e7 [2] 21 ed [2] 36 e6 [2] 2d a8 [2] 10 }

  condition:
    any of them
}