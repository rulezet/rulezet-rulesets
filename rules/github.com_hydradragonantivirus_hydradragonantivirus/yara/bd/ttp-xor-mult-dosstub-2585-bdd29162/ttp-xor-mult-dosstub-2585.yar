rule TTP_XOR_MULT_DOSStub_2585 {
  strings:
    $key_2585 = { 71 ed [2] 05 f5 [2] 42 f7 [2] 05 e6 [2] 4b ea [2] 47 e0 [2] 50 eb [2] 4b a5 [2] 76 }

  condition:
    any of them
}