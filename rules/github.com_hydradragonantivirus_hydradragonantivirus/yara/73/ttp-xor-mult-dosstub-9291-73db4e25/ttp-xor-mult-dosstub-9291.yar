rule TTP_XOR_MULT_DOSStub_9291 {
  strings:
    $key_9291 = { c6 f9 [2] b2 e1 [2] f5 e3 [2] b2 f2 [2] fc fe [2] f0 f4 [2] e7 ff [2] fc b1 [2] c1 }

  condition:
    any of them
}