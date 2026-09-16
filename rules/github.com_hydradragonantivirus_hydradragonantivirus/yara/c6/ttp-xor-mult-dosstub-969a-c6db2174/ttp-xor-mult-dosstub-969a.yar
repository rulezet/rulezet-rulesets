rule TTP_XOR_MULT_DOSStub_969a {
  strings:
    $key_969a = { c2 f2 [2] b6 ea [2] f1 e8 [2] b6 f9 [2] f8 f5 [2] f4 ff [2] e3 f4 [2] f8 ba [2] c5 }

  condition:
    any of them
}