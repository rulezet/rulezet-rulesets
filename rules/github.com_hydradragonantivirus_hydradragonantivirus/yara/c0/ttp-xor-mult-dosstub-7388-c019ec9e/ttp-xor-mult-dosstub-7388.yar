rule TTP_XOR_MULT_DOSStub_7388 {
  strings:
    $key_7388 = { 27 e0 [2] 53 f8 [2] 14 fa [2] 53 eb [2] 1d e7 [2] 11 ed [2] 06 e6 [2] 1d a8 [2] 20 }

  condition:
    any of them
}