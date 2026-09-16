rule TTP_XOR_MULT_DOSStub_4585 {
  strings:
    $key_4585 = { 11 ed [2] 65 f5 [2] 22 f7 [2] 65 e6 [2] 2b ea [2] 27 e0 [2] 30 eb [2] 2b a5 [2] 16 }

  condition:
    any of them
}