rule TTP_XOR_MULT_DOSStub_6288 {
  strings:
    $key_6288 = { 36 e0 [2] 42 f8 [2] 05 fa [2] 42 eb [2] 0c e7 [2] 00 ed [2] 17 e6 [2] 0c a8 [2] 31 }

  condition:
    any of them
}