rule TTP_XOR_MULT_DOSStub_d087 {
  strings:
    $key_d087 = { 84 ef [2] f0 f7 [2] b7 f5 [2] f0 e4 [2] be e8 [2] b2 e2 [2] a5 e9 [2] be a7 [2] 83 }

  condition:
    any of them
}