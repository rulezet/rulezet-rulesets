rule TTP_XOR_MULT_DOSStub_9490 {
  strings:
    $key_9490 = { c0 f8 [2] b4 e0 [2] f3 e2 [2] b4 f3 [2] fa ff [2] f6 f5 [2] e1 fe [2] fa b0 [2] c7 }

  condition:
    any of them
}