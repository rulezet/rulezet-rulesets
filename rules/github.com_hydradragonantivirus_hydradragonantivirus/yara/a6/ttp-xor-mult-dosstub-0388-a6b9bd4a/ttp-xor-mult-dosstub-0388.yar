rule TTP_XOR_MULT_DOSStub_0388 {
  strings:
    $key_0388 = { 57 e0 [2] 23 f8 [2] 64 fa [2] 23 eb [2] 6d e7 [2] 61 ed [2] 76 e6 [2] 6d a8 [2] 50 }

  condition:
    any of them
}