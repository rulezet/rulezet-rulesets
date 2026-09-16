rule TTP_XOR_MULT_DOSStub_d68f {
  strings:
    $key_d68f = { 82 e7 [2] f6 ff [2] b1 fd [2] f6 ec [2] b8 e0 [2] b4 ea [2] a3 e1 [2] b8 af [2] 85 }

  condition:
    any of them
}