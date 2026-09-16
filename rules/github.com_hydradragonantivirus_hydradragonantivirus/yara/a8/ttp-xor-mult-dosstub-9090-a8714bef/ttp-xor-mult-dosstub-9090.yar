rule TTP_XOR_MULT_DOSStub_9090 {
  strings:
    $key_9090 = { c4 f8 [2] b0 e0 [2] f7 e2 [2] b0 f3 [2] fe ff [2] f2 f5 [2] e5 fe [2] fe b0 [2] c3 }

  condition:
    any of them
}