rule TTP_XOR_MULT_DOSStub_88d9 {
  strings:
    $key_88d9 = { dc b1 [2] a8 a9 [2] ef ab [2] a8 ba [2] e6 b6 [2] ea bc [2] fd b7 [2] e6 f9 [2] db }

  condition:
    any of them
}