rule TTP_XOR_MULT_DOSStub_8591 {
  strings:
    $key_8591 = { d1 f9 [2] a5 e1 [2] e2 e3 [2] a5 f2 [2] eb fe [2] e7 f4 [2] f0 ff [2] eb b1 [2] d6 }

  condition:
    any of them
}