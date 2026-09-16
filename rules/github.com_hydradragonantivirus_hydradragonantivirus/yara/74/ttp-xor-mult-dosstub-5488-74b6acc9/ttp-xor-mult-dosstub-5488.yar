rule TTP_XOR_MULT_DOSStub_5488 {
  strings:
    $key_5488 = { 00 e0 [2] 74 f8 [2] 33 fa [2] 74 eb [2] 3a e7 [2] 36 ed [2] 21 e6 [2] 3a a8 [2] 07 }

  condition:
    any of them
}