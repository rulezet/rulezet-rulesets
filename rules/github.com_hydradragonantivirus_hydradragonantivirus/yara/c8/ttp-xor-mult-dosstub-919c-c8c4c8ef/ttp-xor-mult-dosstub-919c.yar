rule TTP_XOR_MULT_DOSStub_919c {
  strings:
    $key_919c = { c5 f4 [2] b1 ec [2] f6 ee [2] b1 ff [2] ff f3 [2] f3 f9 [2] e4 f2 [2] ff bc [2] c2 }

  condition:
    any of them
}