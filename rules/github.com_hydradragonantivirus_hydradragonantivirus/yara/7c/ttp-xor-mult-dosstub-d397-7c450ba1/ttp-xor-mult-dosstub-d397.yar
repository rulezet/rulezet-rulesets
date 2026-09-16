rule TTP_XOR_MULT_DOSStub_d397 {
  strings:
    $key_d397 = { 87 ff [2] f3 e7 [2] b4 e5 [2] f3 f4 [2] bd f8 [2] b1 f2 [2] a6 f9 [2] bd b7 [2] 80 }

  condition:
    any of them
}