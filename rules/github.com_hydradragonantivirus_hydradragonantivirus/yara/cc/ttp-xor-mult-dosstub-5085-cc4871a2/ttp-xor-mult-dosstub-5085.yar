rule TTP_XOR_MULT_DOSStub_5085 {
  strings:
    $key_5085 = { 04 ed [2] 70 f5 [2] 37 f7 [2] 70 e6 [2] 3e ea [2] 32 e0 [2] 25 eb [2] 3e a5 [2] 03 }

  condition:
    any of them
}