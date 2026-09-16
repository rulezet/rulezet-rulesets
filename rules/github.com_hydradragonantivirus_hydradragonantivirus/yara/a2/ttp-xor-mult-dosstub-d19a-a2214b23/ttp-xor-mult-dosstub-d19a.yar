rule TTP_XOR_MULT_DOSStub_d19a {
  strings:
    $key_d19a = { 85 f2 [2] f1 ea [2] b6 e8 [2] f1 f9 [2] bf f5 [2] b3 ff [2] a4 f4 [2] bf ba [2] 82 }

  condition:
    any of them
}