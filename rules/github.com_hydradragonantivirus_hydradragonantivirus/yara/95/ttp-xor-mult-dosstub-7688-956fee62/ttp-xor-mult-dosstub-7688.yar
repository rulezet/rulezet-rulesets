rule TTP_XOR_MULT_DOSStub_7688 {
  strings:
    $key_7688 = { 22 e0 [2] 56 f8 [2] 11 fa [2] 56 eb [2] 18 e7 [2] 14 ed [2] 03 e6 [2] 18 a8 [2] 25 }

  condition:
    any of them
}