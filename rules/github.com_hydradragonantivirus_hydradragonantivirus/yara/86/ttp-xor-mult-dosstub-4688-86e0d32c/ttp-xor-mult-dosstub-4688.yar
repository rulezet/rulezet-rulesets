rule TTP_XOR_MULT_DOSStub_4688 {
  strings:
    $key_4688 = { 12 e0 [2] 66 f8 [2] 21 fa [2] 66 eb [2] 28 e7 [2] 24 ed [2] 33 e6 [2] 28 a8 [2] 15 }

  condition:
    any of them
}