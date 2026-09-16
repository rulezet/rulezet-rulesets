rule TTP_XOR_MULT_DOSStub_d6cc {
  strings:
    $key_d6cc = { 82 a4 [2] f6 bc [2] b1 be [2] f6 af [2] b8 a3 [2] b4 a9 [2] a3 a2 [2] b8 ec [2] 85 }

  condition:
    any of them
}