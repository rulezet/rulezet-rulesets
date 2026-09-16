rule TTP_XOR_MULT_DOSStub_7a88 {
  strings:
    $key_7a88 = { 2e e0 [2] 5a f8 [2] 1d fa [2] 5a eb [2] 14 e7 [2] 18 ed [2] 0f e6 [2] 14 a8 [2] 29 }

  condition:
    any of them
}