rule TTP_XOR_MULT_DOSStub_9380 {
  strings:
    $key_9380 = { c7 e8 [2] b3 f0 [2] f4 f2 [2] b3 e3 [2] fd ef [2] f1 e5 [2] e6 ee [2] fd a0 [2] c0 }

  condition:
    any of them
}