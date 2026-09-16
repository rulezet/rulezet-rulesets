rule TTP_XOR_MULT_DOSStub_2a88 {
  strings:
    $key_2a88 = { 7e e0 [2] 0a f8 [2] 4d fa [2] 0a eb [2] 44 e7 [2] 48 ed [2] 5f e6 [2] 44 a8 [2] 79 }

  condition:
    any of them
}