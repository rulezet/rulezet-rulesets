rule TTP_XOR_MULT_DOSStub_6388 {
  strings:
    $key_6388 = { 37 e0 [2] 43 f8 [2] 04 fa [2] 43 eb [2] 0d e7 [2] 01 ed [2] 16 e6 [2] 0d a8 [2] 30 }

  condition:
    any of them
}