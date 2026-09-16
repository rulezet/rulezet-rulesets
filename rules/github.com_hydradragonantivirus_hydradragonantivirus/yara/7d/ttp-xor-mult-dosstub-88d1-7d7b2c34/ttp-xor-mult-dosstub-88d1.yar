rule TTP_XOR_MULT_DOSStub_88d1 {
  strings:
    $key_88d1 = { dc b9 [2] a8 a1 [2] ef a3 [2] a8 b2 [2] e6 be [2] ea b4 [2] fd bf [2] e6 f1 [2] db }

  condition:
    any of them
}