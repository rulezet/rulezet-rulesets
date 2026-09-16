rule TTP_XOR_MULT_DOSStub_88d5 {
  strings:
    $key_88d5 = { dc bd [2] a8 a5 [2] ef a7 [2] a8 b6 [2] e6 ba [2] ea b0 [2] fd bb [2] e6 f5 [2] db }

  condition:
    any of them
}