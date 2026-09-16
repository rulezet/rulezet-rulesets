rule TTP_XOR_MULT_DOSStub_9790 {
  strings:
    $key_9790 = { c3 f8 [2] b7 e0 [2] f0 e2 [2] b7 f3 [2] f9 ff [2] f5 f5 [2] e2 fe [2] f9 b0 [2] c4 }

  condition:
    any of them
}