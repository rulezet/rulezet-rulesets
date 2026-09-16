rule TTP_XOR_MULT_DOSStub_909a {
  strings:
    $key_909a = { c4 f2 [2] b0 ea [2] f7 e8 [2] b0 f9 [2] fe f5 [2] f2 ff [2] e5 f4 [2] fe ba [2] c3 }

  condition:
    any of them
}