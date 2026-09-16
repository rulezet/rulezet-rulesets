rule TTP_XOR_MULT_DOSStub_9796 {
  strings:
    $key_9796 = { c3 fe [2] b7 e6 [2] f0 e4 [2] b7 f5 [2] f9 f9 [2] f5 f3 [2] e2 f8 [2] f9 b6 [2] c4 }

  condition:
    any of them
}