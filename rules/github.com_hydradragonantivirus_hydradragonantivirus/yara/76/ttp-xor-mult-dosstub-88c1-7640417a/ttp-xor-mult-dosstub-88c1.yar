rule TTP_XOR_MULT_DOSStub_88c1 {
  strings:
    $key_88c1 = { dc a9 [2] a8 b1 [2] ef b3 [2] a8 a2 [2] e6 ae [2] ea a4 [2] fd af [2] e6 e1 [2] db }

  condition:
    any of them
}