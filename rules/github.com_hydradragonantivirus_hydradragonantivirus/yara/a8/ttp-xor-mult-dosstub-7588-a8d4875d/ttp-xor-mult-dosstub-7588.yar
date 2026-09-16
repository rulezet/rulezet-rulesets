rule TTP_XOR_MULT_DOSStub_7588 {
  strings:
    $key_7588 = { 21 e0 [2] 55 f8 [2] 12 fa [2] 55 eb [2] 1b e7 [2] 17 ed [2] 00 e6 [2] 1b a8 [2] 26 }

  condition:
    any of them
}