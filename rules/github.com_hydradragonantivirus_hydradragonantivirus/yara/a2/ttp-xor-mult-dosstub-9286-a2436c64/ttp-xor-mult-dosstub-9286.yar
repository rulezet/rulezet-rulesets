rule TTP_XOR_MULT_DOSStub_9286 {
  strings:
    $key_9286 = { c6 ee [2] b2 f6 [2] f5 f4 [2] b2 e5 [2] fc e9 [2] f0 e3 [2] e7 e8 [2] fc a6 [2] c1 }

  condition:
    any of them
}