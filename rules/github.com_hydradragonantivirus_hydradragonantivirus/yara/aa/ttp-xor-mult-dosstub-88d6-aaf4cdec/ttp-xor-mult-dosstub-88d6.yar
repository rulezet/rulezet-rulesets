rule TTP_XOR_MULT_DOSStub_88d6 {
  strings:
    $key_88d6 = { dc be [2] a8 a6 [2] ef a4 [2] a8 b5 [2] e6 b9 [2] ea b3 [2] fd b8 [2] e6 f6 [2] db }

  condition:
    any of them
}