rule TTP_XOR_MULT_DOSStub_d1df {
  strings:
    $key_d1df = { 85 b7 [2] f1 af [2] b6 ad [2] f1 bc [2] bf b0 [2] b3 ba [2] a4 b1 [2] bf ff [2] 82 }

  condition:
    any of them
}