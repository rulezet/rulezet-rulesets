rule TTP_XOR_MULT_DOSStub_e6d2 {
  strings:
    $key_e6d2 = { b2 ba [2] c6 a2 [2] 81 a0 [2] c6 b1 [2] 88 bd [2] 84 b7 [2] 93 bc [2] 88 f2 [2] b5 }

  condition:
    any of them
}