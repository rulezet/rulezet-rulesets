rule TTP_XOR_MULT_DOSStub_9480 {
  strings:
    $key_9480 = { c0 e8 [2] b4 f0 [2] f3 f2 [2] b4 e3 [2] fa ef [2] f6 e5 [2] e1 ee [2] fa a0 [2] c7 }

  condition:
    any of them
}