rule TTP_XOR_MULT_DOSStub_5585 {
  strings:
    $key_5585 = { 01 ed [2] 75 f5 [2] 32 f7 [2] 75 e6 [2] 3b ea [2] 37 e0 [2] 20 eb [2] 3b a5 [2] 06 }

  condition:
    any of them
}