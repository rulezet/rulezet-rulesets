rule TTP_XOR_MULT_DOSStub_3188 {
  strings:
    $key_3188 = { 65 e0 [2] 11 f8 [2] 56 fa [2] 11 eb [2] 5f e7 [2] 53 ed [2] 44 e6 [2] 5f a8 [2] 62 }

  condition:
    any of them
}