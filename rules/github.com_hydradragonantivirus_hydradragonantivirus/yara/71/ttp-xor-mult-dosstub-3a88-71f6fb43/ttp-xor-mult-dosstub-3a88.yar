rule TTP_XOR_MULT_DOSStub_3a88 {
  strings:
    $key_3a88 = { 6e e0 [2] 1a f8 [2] 5d fa [2] 1a eb [2] 54 e7 [2] 58 ed [2] 4f e6 [2] 54 a8 [2] 69 }

  condition:
    any of them
}