rule TTP_XOR_MULT_DOSStub_d48f {
  strings:
    $key_d48f = { 80 e7 [2] f4 ff [2] b3 fd [2] f4 ec [2] ba e0 [2] b6 ea [2] a1 e1 [2] ba af [2] 87 }

  condition:
    any of them
}