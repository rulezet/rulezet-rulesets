rule TTP_XOR_MULT_DOSStub_d990 {
  strings:
    $key_d990 = { 8d f8 [2] f9 e0 [2] be e2 [2] f9 f3 [2] b7 ff [2] bb f5 [2] ac fe [2] b7 b0 [2] 8a }

  condition:
    any of them
}