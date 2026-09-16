rule TTP_XOR_MULT_DOSStub_90ca {
  strings:
    $key_90ca = { c4 a2 [2] b0 ba [2] f7 b8 [2] b0 a9 [2] fe a5 [2] f2 af [2] e5 a4 [2] fe ea [2] c3 }

  condition:
    any of them
}