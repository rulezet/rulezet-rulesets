rule TTP_XOR_MULT_DOSStub_d99a {
  strings:
    $key_d99a = { 8d f2 [2] f9 ea [2] be e8 [2] f9 f9 [2] b7 f5 [2] bb ff [2] ac f4 [2] b7 ba [2] 8a }

  condition:
    any of them
}