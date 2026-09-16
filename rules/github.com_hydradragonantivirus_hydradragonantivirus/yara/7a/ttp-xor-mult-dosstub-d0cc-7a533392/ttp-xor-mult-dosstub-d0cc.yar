rule TTP_XOR_MULT_DOSStub_d0cc {
  strings:
    $key_d0cc = { 84 a4 [2] f0 bc [2] b7 be [2] f0 af [2] be a3 [2] b2 a9 [2] a5 a2 [2] be ec [2] 83 }

  condition:
    any of them
}