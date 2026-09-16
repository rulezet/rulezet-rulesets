rule TTP_XOR_MULT_DOSStub_869c {
  strings:
    $key_869c = { d2 f4 [2] a6 ec [2] e1 ee [2] a6 ff [2] e8 f3 [2] e4 f9 [2] f3 f2 [2] e8 bc [2] d5 }

  condition:
    any of them
}