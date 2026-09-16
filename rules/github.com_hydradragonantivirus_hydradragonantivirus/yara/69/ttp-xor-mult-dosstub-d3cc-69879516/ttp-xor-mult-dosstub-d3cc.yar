rule TTP_XOR_MULT_DOSStub_d3cc {
  strings:
    $key_d3cc = { 87 a4 [2] f3 bc [2] b4 be [2] f3 af [2] bd a3 [2] b1 a9 [2] a6 a2 [2] bd ec [2] 80 }

  condition:
    any of them
}