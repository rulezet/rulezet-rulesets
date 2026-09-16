rule TTP_XOR_MULT_DOSStub_6485 {
  strings:
    $key_6485 = { 30 ed [2] 44 f5 [2] 03 f7 [2] 44 e6 [2] 0a ea [2] 06 e0 [2] 11 eb [2] 0a a5 [2] 37 }

  condition:
    any of them
}