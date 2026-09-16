rule TTP_XOR_MULT_DOSStub_1588 {
  strings:
    $key_1588 = { 41 e0 [2] 35 f8 [2] 72 fa [2] 35 eb [2] 7b e7 [2] 77 ed [2] 60 e6 [2] 7b a8 [2] 46 }

  condition:
    any of them
}