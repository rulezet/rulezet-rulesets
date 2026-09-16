rule TTP_XOR_MULT_DOSStub_4a88 {
  strings:
    $key_4a88 = { 1e e0 [2] 6a f8 [2] 2d fa [2] 6a eb [2] 24 e7 [2] 28 ed [2] 3f e6 [2] 24 a8 [2] 19 }

  condition:
    any of them
}