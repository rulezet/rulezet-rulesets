rule TTP_XOR_MULT_DOSStub_1a88 {
  strings:
    $key_1a88 = { 4e e0 [2] 3a f8 [2] 7d fa [2] 3a eb [2] 74 e7 [2] 78 ed [2] 6f e6 [2] 74 a8 [2] 49 }

  condition:
    any of them
}