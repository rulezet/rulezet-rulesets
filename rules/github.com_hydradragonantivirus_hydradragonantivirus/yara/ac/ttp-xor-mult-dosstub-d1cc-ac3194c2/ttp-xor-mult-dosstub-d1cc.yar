rule TTP_XOR_MULT_DOSStub_d1cc {
  strings:
    $key_d1cc = { 85 a4 [2] f1 bc [2] b6 be [2] f1 af [2] bf a3 [2] b3 a9 [2] a4 a2 [2] bf ec [2] 82 }

  condition:
    any of them
}