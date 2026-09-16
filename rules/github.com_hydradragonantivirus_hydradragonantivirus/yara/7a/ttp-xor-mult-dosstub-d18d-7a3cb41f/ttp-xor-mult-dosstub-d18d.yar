rule TTP_XOR_MULT_DOSStub_d18d {
  strings:
    $key_d18d = { 85 e5 [2] f1 fd [2] b6 ff [2] f1 ee [2] bf e2 [2] b3 e8 [2] a4 e3 [2] bf ad [2] 82 }

  condition:
    any of them
}