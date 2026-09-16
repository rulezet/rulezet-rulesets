rule TTP_XOR_MULT_DOSStub_e6ca {
  strings:
    $key_e6ca = { b2 a2 [2] c6 ba [2] 81 b8 [2] c6 a9 [2] 88 a5 [2] 84 af [2] 93 a4 [2] 88 ea [2] b5 }

  condition:
    any of them
}