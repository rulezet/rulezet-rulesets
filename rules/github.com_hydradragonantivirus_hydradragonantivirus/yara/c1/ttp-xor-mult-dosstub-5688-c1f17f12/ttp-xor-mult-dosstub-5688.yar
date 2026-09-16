rule TTP_XOR_MULT_DOSStub_5688 {
  strings:
    $key_5688 = { 02 e0 [2] 76 f8 [2] 31 fa [2] 76 eb [2] 38 e7 [2] 34 ed [2] 23 e6 [2] 38 a8 [2] 05 }

  condition:
    any of them
}