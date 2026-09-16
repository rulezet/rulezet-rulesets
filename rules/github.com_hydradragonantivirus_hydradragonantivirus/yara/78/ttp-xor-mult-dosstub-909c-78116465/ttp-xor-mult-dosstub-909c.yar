rule TTP_XOR_MULT_DOSStub_909c {
  strings:
    $key_909c = { c4 f4 [2] b0 ec [2] f7 ee [2] b0 ff [2] fe f3 [2] f2 f9 [2] e5 f2 [2] fe bc [2] c3 }

  condition:
    any of them
}