rule TTP_XOR_MULT_DOSStub_90c8 {
  strings:
    $key_90c8 = { c4 a0 [2] b0 b8 [2] f7 ba [2] b0 ab [2] fe a7 [2] f2 ad [2] e5 a6 [2] fe e8 [2] c3 }

  condition:
    any of them
}