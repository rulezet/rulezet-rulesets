rule TTP_XOR_MULT_DOSStub_0a88 {
  strings:
    $key_0a88 = { 5e e0 [2] 2a f8 [2] 6d fa [2] 2a eb [2] 64 e7 [2] 68 ed [2] 7f e6 [2] 64 a8 [2] 59 }

  condition:
    any of them
}