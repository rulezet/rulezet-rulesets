rule TTP_XOR_MULT_DOSStub_f585 {
  strings:
    $key_f585 = { a1 ed [2] d5 f5 [2] 92 f7 [2] d5 e6 [2] 9b ea [2] 97 e0 [2] 80 eb [2] 9b a5 [2] a6 }

  condition:
    any of them
}