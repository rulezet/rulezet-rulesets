rule TTP_XOR_MULT_DOSStub_9690 {
  strings:
    $key_9690 = { c2 f8 [2] b6 e0 [2] f1 e2 [2] b6 f3 [2] f8 ff [2] f4 f5 [2] e3 fe [2] f8 b0 [2] c5 }

  condition:
    any of them
}