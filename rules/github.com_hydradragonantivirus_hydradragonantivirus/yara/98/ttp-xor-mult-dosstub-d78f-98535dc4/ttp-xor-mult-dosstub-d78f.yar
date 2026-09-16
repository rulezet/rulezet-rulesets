rule TTP_XOR_MULT_DOSStub_d78f {
  strings:
    $key_d78f = { 83 e7 [2] f7 ff [2] b0 fd [2] f7 ec [2] b9 e0 [2] b5 ea [2] a2 e1 [2] b9 af [2] 84 }

  condition:
    any of them
}