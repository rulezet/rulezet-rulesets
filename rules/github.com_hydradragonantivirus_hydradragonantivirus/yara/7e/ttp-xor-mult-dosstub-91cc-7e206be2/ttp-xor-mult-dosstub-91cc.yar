rule TTP_XOR_MULT_DOSStub_91cc {
  strings:
    $key_91cc = { c5 a4 [2] b1 bc [2] f6 be [2] b1 af [2] ff a3 [2] f3 a9 [2] e4 a2 [2] ff ec [2] c2 }

  condition:
    any of them
}