rule TTP_XOR_MULT_DOSStub_9081 {
  strings:
    $key_9081 = { c4 e9 [2] b0 f1 [2] f7 f3 [2] b0 e2 [2] fe ee [2] f2 e4 [2] e5 ef [2] fe a1 [2] c3 }

  condition:
    any of them
}