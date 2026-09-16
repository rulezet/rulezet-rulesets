rule TTP_XOR_MULT_DOSStub_e698 {
  strings:
    $key_e698 = { b2 f0 [2] c6 e8 [2] 81 ea [2] c6 fb [2] 88 f7 [2] 84 fd [2] 93 f6 [2] 88 b8 [2] b5 }

  condition:
    any of them
}