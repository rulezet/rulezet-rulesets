rule TTP_XOR_MULT_DOSStub_3288 {
  strings:
    $key_3288 = { 66 e0 [2] 12 f8 [2] 55 fa [2] 12 eb [2] 5c e7 [2] 50 ed [2] 47 e6 [2] 5c a8 [2] 61 }

  condition:
    any of them
}