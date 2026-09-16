rule TTP_XOR_MULT_DOSStub_d79a {
  strings:
    $key_d79a = { 83 f2 [2] f7 ea [2] b0 e8 [2] f7 f9 [2] b9 f5 [2] b5 ff [2] a2 f4 [2] b9 ba [2] 84 }

  condition:
    any of them
}