rule TTP_XOR_MULT_DOSStub_9296 {
  strings:
    $key_9296 = { c6 fe [2] b2 e6 [2] f5 e4 [2] b2 f5 [2] fc f9 [2] f0 f3 [2] e7 f8 [2] fc b6 [2] c1 }

  condition:
    any of them
}