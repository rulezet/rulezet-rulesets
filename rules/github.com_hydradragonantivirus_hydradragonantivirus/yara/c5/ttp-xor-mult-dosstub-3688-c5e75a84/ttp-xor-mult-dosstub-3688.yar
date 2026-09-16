rule TTP_XOR_MULT_DOSStub_3688 {
  strings:
    $key_3688 = { 62 e0 [2] 16 f8 [2] 51 fa [2] 16 eb [2] 58 e7 [2] 54 ed [2] 43 e6 [2] 58 a8 [2] 65 }

  condition:
    any of them
}