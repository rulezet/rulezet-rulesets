rule TTP_XOR_MULT_DOSStub_d19b {
  strings:
    $key_d19b = { 85 f3 [2] f1 eb [2] b6 e9 [2] f1 f8 [2] bf f4 [2] b3 fe [2] a4 f5 [2] bf bb [2] 82 }

  condition:
    any of them
}